//! Reading an account's credentials at sign-in, and only then.
//!
//! - 1Password: `op inject` fills in the username and password of every account that signs in at that
//!   moment, in one start of `op`. The
//!   1Password app asks the user itself. Stopping the sign-in kills `op`, and
//!   so does a 1Password that gives no answer within 2 minutes.
//! - System store: the password from the Keychain or Credential Manager, after
//!   Touch ID or Windows Hello confirms it is the user.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::accounts::{Account, Store};
use crate::secrets::{SecretStore, SystemStore};

pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Why credentials could not be read; the message is shown as is.
#[derive(Debug, PartialEq)]
pub struct CredError(pub String);

/// How long the 1Password read may take, its prompt included.
const OP_TIMEOUT: Duration = Duration::from_secs(120);
/// How often a running `op` is checked for an end, a stop or the timeout.
const OP_POLL: Duration = Duration::from_millis(100);

fn password_key(id: Uuid) -> String {
    format!("account:{id}")
}

pub fn save_password(id: Uuid, password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("Vul het wachtwoord in".into());
    }
    SystemStore.set(&password_key(id), password)
}

pub fn delete_password(id: Uuid) -> Result<(), String> {
    SystemStore.delete(&password_key(id))
}

/// Reads the account's username and password, and says how many accounts 1Password answered for in the
/// same start of `op` (1 for the system store). Setting `cancel` stops a 1Password read: this account's part
/// ends with an error, and `op` is killed once nobody waits for it; the caller tells a stop from a failure by
/// `cancel` itself.
pub async fn read(
    account: &Account,
    cancel: &Arc<AtomicBool>,
    op: &OpReader,
) -> Result<(Credentials, usize), CredError> {
    match account.store {
        Store::OnePassword => {
            let reference = account
                .op_ref
                .clone()
                .ok_or_else(|| CredError("Geen 1Password-item ingesteld".into()))?;
            op.read(reference, cancel).await
        }
        Store::System => {
            confirm_user(&confirm_text(&account.label)).await?;
            let password = SystemStore
                .get(&password_key(account.id))
                .map_err(CredError)?
                .ok_or_else(|| {
                    CredError(
                        "Geen wachtwoord in de sleutelhanger. Vul het opnieuw in bij Bewerken."
                            .into(),
                    )
                })?;
            Ok((
                Credentials {
                    username: account.username.clone(),
                    password,
                },
                1,
            ))
        }
    }
}

/// One sign-in's wish for its 1Password item.
struct OpRequest {
    reference: String,
    cancel: Arc<AtomicBool>,
    answer: tokio::sync::oneshot::Sender<OpAnswer>,
}

/// The credentials and how many accounts were read in the same start of `op`.
type OpAnswer = Result<(Credentials, usize), CredError>;

/// How long a read waits for other sign-ins to join it. Alles inloggen starts its sign-ins within a few
/// milliseconds of each other; one start of `op` for all of them saves seconds, and this costs none to notice.
const OP_GATHER: Duration = Duration::from_millis(40);

/// The 1Password reads of sign-ins that run side by side, taken together: every start of `op` costs a second
/// or two (it talks to the 1Password app each time), whatever it reads. So one read is one start of `op` for
/// every sign-in that waits by then, and the user answers 1Password's prompt once.
#[derive(Default)]
pub struct OpReader {
    waiting: Mutex<Vec<OpRequest>>,
    /// Held by the sign-in whose turn it is to start `op`.
    turn: tokio::sync::Mutex<()>,
}

impl OpReader {
    async fn read(&self, reference: String, cancel: &Arc<AtomicBool>) -> OpAnswer {
        self.read_through(reference, cancel, read_batch).await
    }

    /// Queues the wish, then takes a turn: whoever has the turn reads for everyone that waits, itself
    /// included, through `run`. A wish that another sign-in's turn already served finds its turn empty.
    async fn read_through(
        &self,
        reference: String,
        cancel: &Arc<AtomicBool>,
        run: fn(Vec<OpRequest>),
    ) -> OpAnswer {
        let (answer, answered) = tokio::sync::oneshot::channel();
        self.waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(OpRequest {
                reference,
                cancel: cancel.clone(),
                answer,
            });
        {
            let _turn = self.turn.lock().await;
            tokio::time::sleep(OP_GATHER).await;
            let batch =
                std::mem::take(&mut *self.waiting.lock().unwrap_or_else(|e| e.into_inner()));
            if !batch.is_empty() {
                // On a thread of its own, and to its end even when this sign-in is stopped meanwhile: the
                // others in the batch still wait for their answer.
                let _ = tokio::task::spawn_blocking(move || run(batch)).await;
            }
        }
        answered
            .await
            .unwrap_or_else(|_| Err(CredError("1Password gaf geen antwoord".into())))
    }
}

/// Reads for every request in one go and answers each. Runs on a blocking thread.
fn read_batch(batch: Vec<OpRequest>) {
    let stopped = || CredError("Inloggen gestopt".into());
    let (live, gone): (Vec<OpRequest>, Vec<OpRequest>) = batch
        .into_iter()
        .partition(|r| !r.cancel.load(Ordering::SeqCst));
    for request in gone {
        let _ = request.answer.send(Err(stopped()));
    }
    let Some(op) = op_binary() else {
        for request in live {
            let _ = request.answer.send(Err(CredError("De 1Password-CLI (op) is niet gevonden. Installeer hem en zet de koppeling met de 1Password-app aan.".into())));
        }
        return;
    };
    // One deadline for the whole read: the user answers 1Password's prompt once.
    let deadline = Instant::now() + OP_TIMEOUT;
    let (together, alone): (Vec<OpRequest>, Vec<OpRequest>) = live
        .into_iter()
        .partition(|r| plain_reference(&r.reference));
    let mut one_by_one = alone;
    if !together.is_empty() {
        let references: Vec<&str> = together.iter().map(|r| r.reference.as_str()).collect();
        let boundary = format!("--eb-mcp-{}--", Uuid::new_v4().simple());
        // `op` is stopped only when nobody in the batch waits for it any more.
        let nobody_waits = || together.iter().all(|r| r.cancel.load(Ordering::SeqCst));
        let read = run_op(
            Command::new(&op).arg("inject"),
            Some(batch_template(&references, &boundary).as_bytes()),
            &nobody_waits,
            deadline,
        );
        let count = together.len();
        match read {
            Ok(output) => match split_batch(&output, &boundary, count) {
                Some(found) => {
                    for (request, (username, password)) in together.into_iter().zip(found) {
                        let answer = if request.cancel.load(Ordering::SeqCst) {
                            Err(stopped())
                        } else if username.is_empty() || password.is_empty() {
                            Err(CredError(format!(
                                "Het item {} heeft geen gebruikersnaam of wachtwoord",
                                request.reference
                            )))
                        } else {
                            Ok((Credentials { username, password }, count))
                        };
                        let _ = request.answer.send(answer);
                    }
                }
                None => {
                    for request in together {
                        let _ = request
                            .answer
                            .send(Err(CredError("1Password gaf geen leesbare tekst".into())));
                    }
                }
            },
            // 1Password said no to the whole read (locked, no consent, no answer, stopped): the same holds
            // for every account in it, and asking again per account would put up a prompt for each.
            Err(OpFailure::Refused(error)) => {
                for request in together {
                    let _ = request.answer.send(Err(CredError(error.0.clone())));
                }
            }
            // One item of several is wrong and `op` does not say which in a way to rely on: each account
            // is read on its own, so the right one gets the message.
            Err(OpFailure::Item(_)) if count > 1 => one_by_one.extend(together),
            Err(OpFailure::Item(stderr)) => {
                for request in together {
                    let _ = request
                        .answer
                        .send(Err(CredError(op_message(&stderr, &request.reference))));
                }
            }
        }
    }
    for request in one_by_one {
        let answer = if request.cancel.load(Ordering::SeqCst) {
            Err(stopped())
        } else {
            read_one(&op, &request.reference, &request.cancel, deadline).map(|c| (c, 1))
        };
        let _ = request.answer.send(answer);
    }
}

/// Why a start of `op` gave nothing.
enum OpFailure {
    /// It holds for whatever was asked: 1Password is locked or gave no consent or no answer, or the read was stopped.
    Refused(CredError),
    /// `op` ran and refused what was asked for; its stderr says what.
    Item(String),
}

/// Whether `op`'s stderr is about 1Password itself and not about the item that was asked for.
fn about_1password(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("locked")
        || lower.contains("authorization")
        || lower.contains("not signed in")
        || lower.contains("sign in")
}

/// Runs `op` once and gives what it wrote.
fn run_op(
    command: &mut Command,
    input: Option<&[u8]>,
    cancelled: &dyn Fn() -> bool,
    deadline: Instant,
) -> Result<String, OpFailure> {
    let refused = |message: &str| OpFailure::Refused(CredError(message.into()));
    let waited = wait_child(command, input, cancelled, deadline)
        .map_err(|e| OpFailure::Refused(CredError(format!("1Password-CLI start niet: {e}"))))?;
    let output = match waited {
        Waited::Exited(output) => output,
        Waited::Cancelled => return Err(refused("Inloggen gestopt")),
        Waited::TimedOut => {
            return Err(refused(
                "1Password gaf binnen 2 minuten geen antwoord. Ontgrendel 1Password en probeer opnieuw.",
            ));
        }
    };
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(if about_1password(&detail) {
            OpFailure::Refused(CredError(op_message(&detail, "")))
        } else {
            OpFailure::Item(detail)
        });
    }
    String::from_utf8(output.stdout).map_err(|_| refused("1Password gaf geen leesbare tekst"))
}

/// What Touch ID and Windows Hello show: "EB MCP wil het wachtwoord van Studio Noord gebruiken".
fn confirm_text(label: &str) -> String {
    format!("EB MCP wil het wachtwoord van {label} gebruiken")
}

/// Whether both parts of `op://vault/item` hold only what a reference inside an `op inject` template may:
/// letters, digits, `-`, `_` and `.`. The references the item picker makes are ids, which always do; one typed
/// by hand with a name that has a space in it does not.
fn plain_reference(reference: &str) -> bool {
    reference.strip_prefix("op://").is_some_and(|rest| {
        rest.split('/').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
    })
}

/// The username and password out of what `op inject` wrote for the two-line template: the username is the
/// first line, the password the rest, without the line end `op` may put after it.
fn split_injected(output: &str) -> Option<(String, String)> {
    let (username, password) = output.split_once('\n')?;
    let password = password
        .strip_suffix('\n')
        .unwrap_or(password)
        .trim_end_matches('\r');
    Some((
        username.trim_end_matches('\r').to_owned(),
        password.to_owned(),
    ))
}

/// The template `op inject` fills in for several items at once: a line of its own between and around them,
/// then per item its username on one line and its password on the next.
fn batch_template(references: &[&str], boundary: &str) -> String {
    let mut template = String::from(boundary);
    for reference in references {
        template.push_str(&format!(
            "\n{{{{ {reference}/username }}}}\n{{{{ {reference}/password }}}}\n{boundary}"
        ));
    }
    template
}

/// The username and password of each of `count` items out of what `op inject` wrote for `batch_template`.
fn split_batch(output: &str, boundary: &str, count: usize) -> Option<Vec<(String, String)>> {
    let mut parts = output.split(boundary);
    // Before the first boundary there is nothing.
    parts.next()?;
    let found: Vec<(String, String)> = parts
        .take(count)
        .map(|part| {
            let part = part
                .strip_prefix("\r\n")
                .or_else(|| part.strip_prefix('\n'))?;
            split_injected(part)
        })
        .collect::<Option<_>>()?;
    (found.len() == count).then_some(found)
}

/// One item on its own: through `op inject` when its reference can stand in a template, field by field
/// when it cannot.
fn read_one(
    op: &std::path::Path,
    reference: &str,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Credentials, CredError> {
    let cancelled = || cancel.load(Ordering::SeqCst);
    let run = |command: &mut Command, input: Option<&[u8]>| -> Result<String, CredError> {
        run_op(command, input, &cancelled, deadline).map_err(|failure| match failure {
            OpFailure::Refused(error) => error,
            OpFailure::Item(stderr) => CredError(op_message(&stderr, reference)),
        })
    };
    let (username, password) = if plain_reference(reference) {
        let boundary = format!("--eb-mcp-{}--", Uuid::new_v4().simple());
        let output = run(
            Command::new(op).arg("inject"),
            Some(batch_template(&[reference], &boundary).as_bytes()),
        )?;
        split_batch(&output, &boundary, 1)
            .and_then(|mut found| found.pop())
            .ok_or_else(|| CredError("1Password gaf geen leesbare tekst".into()))?
    } else {
        let field = |name: &str| {
            run(
                Command::new(op).args(["read", "--no-newline", &format!("{reference}/{name}")]),
                None,
            )
        };
        (field("username")?, field("password")?)
    };
    if username.is_empty() || password.is_empty() {
        return Err(CredError(format!(
            "Het item {reference} heeft geen gebruikersnaam of wachtwoord"
        )));
    }
    Ok(Credentials { username, password })
}

/// How a child process ended under `wait_child`.
#[derive(Debug)]
enum Waited {
    Exited(Output),
    /// `cancel` was set; the child was killed.
    Cancelled,
    /// The deadline passed; the child was killed.
    TimedOut,
}

/// Runs `command` to its end, unless `cancelled` says so or `deadline` passes first: then the child is killed.
/// `input` is written to its standard input, which is then closed. Its output is read on threads meanwhile,
/// so a full pipe never holds the child up.
fn wait_child(
    command: &mut Command,
    input: Option<&[u8]>,
    cancelled: &dyn Fn() -> bool,
    deadline: Instant,
) -> std::io::Result<Waited> {
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        let input = input.to_vec();
        // On its own thread: a child that does not read must not hold up the wait for a stop or the deadline.
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    loop {
        let stopped = match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Waited::Exited(Output {
                    status,
                    stdout: stdout.join().unwrap_or_default(),
                    stderr: stderr.join().unwrap_or_default(),
                }));
            }
            Ok(None) if cancelled() => Ok(Waited::Cancelled),
            Ok(None) if Instant::now() >= deadline => Ok(Waited::TimedOut),
            Ok(None) => {
                std::thread::sleep(OP_POLL);
                continue;
            }
            Err(e) => Err(e),
        };
        let _ = child.kill();
        let _ = child.wait();
        // The reader threads end once the pipes close; whatever they read is dropped unseen.
        drop((stdout, stderr));
        return stopped;
    }
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buffer);
        }
        buffer
    })
}

/// A login in 1Password, as the picker shows it. Never carries a password.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpItem {
    /// `op://<vault id>/<item id>`: ids keep working when the item or vault is renamed.
    pub reference: String,
    pub title: String,
    pub vault: String,
    pub username: String,
    /// The item is for e-Boekhouden: its website or title says so.
    pub suggested: bool,
}

/// Why the list could not be read. The picker shows a fitting notice per kind.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(tag = "kind", content = "message", rename_all = "camelCase")]
pub enum OpListError {
    /// No `op` binary on this machine.
    Missing,
    /// 1Password is locked, or the user declined the prompt.
    Locked,
    Other(String),
}

/// Lists the Login items through `op item list`. The 1Password app asks the user for consent itself.
pub async fn op_items() -> Result<Vec<OpItem>, OpListError> {
    tokio::task::spawn_blocking(|| {
        let op = op_binary().ok_or(OpListError::Missing)?;
        let output = Command::new(&op)
            .args(["item", "list", "--categories", "Login", "--format", "json"])
            .output()
            .map_err(|e| OpListError::Other(format!("1Password-CLI start niet: {e}")))?;
        if !output.status.success() {
            return Err(list_error(&String::from_utf8_lossy(&output.stderr)));
        }
        parse_items(&output.stdout)
    })
    .await
    .map_err(|e| OpListError::Other(e.to_string()))?
}

fn list_error(stderr: &str) -> OpListError {
    let lower = stderr.to_lowercase();
    if lower.contains("locked")
        || lower.contains("authorization")
        || lower.contains("signed in")
        || lower.contains("sign in")
        || lower.contains("dismissed")
    {
        OpListError::Locked
    } else {
        // The list's stderr holds no secrets; its first line helps when something odd happens.
        let line = stderr
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or_default();
        let line = line.split_once("] ").map_or(line, |(_, rest)| rest).trim();
        OpListError::Other(if line.is_empty() {
            "1Password gaf geen lijst met items".into()
        } else {
            format!("1Password gaf geen lijst met items: {line}")
        })
    }
}

#[derive(serde::Deserialize)]
struct RawItem {
    id: String,
    #[serde(default)]
    title: String,
    vault: RawVault,
    #[serde(default)]
    additional_information: Option<String>,
    #[serde(default)]
    urls: Vec<RawUrl>,
}

#[derive(serde::Deserialize)]
struct RawVault {
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(serde::Deserialize)]
struct RawUrl {
    #[serde(default)]
    href: String,
}

/// Parses `op item list --format json`, e-Boekhouden items first, then by title.
pub fn parse_items(json: &[u8]) -> Result<Vec<OpItem>, OpListError> {
    // `op` prints nothing at all when there are no items.
    if json.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let raw: Vec<RawItem> = serde_json::from_slice(json).map_err(|_| {
        OpListError::Other("1Password gaf een lijst die EB MCP niet kan lezen".into())
    })?;
    let mut items: Vec<OpItem> = raw
        .into_iter()
        .filter(|r| !r.id.is_empty() && !r.vault.id.is_empty())
        .map(|r| {
            let suggested = r.title.to_lowercase().contains("boekhouden")
                || r.urls
                    .iter()
                    .any(|u| u.href.to_lowercase().contains("e-boekhouden.nl"));
            OpItem {
                reference: format!("op://{}/{}", r.vault.id, r.id),
                title: r.title,
                vault: r.vault.name,
                username: r.additional_information.unwrap_or_default(),
                suggested,
            }
        })
        .collect();
    items.sort_by(|a, b| {
        b.suggested
            .cmp(&a.suggested)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
    Ok(items)
}

/// Turns `op`'s stderr into one line for the user, without echoing anything secret.
pub fn op_message(stderr: &str, reference: &str) -> String {
    let lower = stderr.to_lowercase();
    if lower.contains("isn't an item") || lower.contains("not found") || lower.contains("no item") {
        format!("1Password vindt {reference} niet. Kies het item opnieuw bij Bewerken.")
    } else if lower.contains("locked")
        || lower.contains("authorization")
        || lower.contains("not signed in")
        || lower.contains("sign in")
    {
        "1Password is vergrendeld of gaf geen toestemming. Ontgrendel 1Password en probeer opnieuw."
            .into()
    } else if lower.contains("does not have a field") || lower.contains("no field") {
        format!("Het item {reference} heeft geen veld username of password")
    } else {
        format!("1Password gaf geen gegevens voor {reference}")
    }
}

fn op_binary() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> =
        vec!["/opt/homebrew/bin/op".into(), "/usr/local/bin/op".into()];
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(local)
                .join("Microsoft")
                .join("WinGet")
                .join("Links")
                .join("op.exe"),
        );
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            candidates.push(dir.join(if cfg!(windows) { "op.exe" } else { "op" }));
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// Touch ID (or the account password) on macOS, Windows Hello on Windows, showing `reason` as is.
async fn confirm_user(reason: &str) -> Result<(), CredError> {
    #[cfg(target_os = "macos")]
    {
        return mac::confirm(reason).await;
    }
    #[cfg(target_os = "windows")]
    {
        return win::confirm(reason).await;
    }
    #[allow(unreachable_code)]
    {
        let _ = reason;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use super::CredError;
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::Mutex;

    pub async fn confirm(reason: &str) -> Result<(), CredError> {
        // Everything Objective-C stays in this block, so nothing that is not Send lives across the await.
        let rx = {
            let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
            let tx = Mutex::new(Some(tx));
            let context = unsafe { LAContext::new() };
            // The reply keeps the context alive until macOS answers, then lets it go.
            let keep = Mutex::new(Some(context.clone()));
            let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
                let result = if ok.as_bool() {
                    Ok(())
                } else {
                    // SAFETY: LocalAuthentication passes a valid NSError or null.
                    let code = unsafe { error.as_ref() }.map(|e| e.code()).unwrap_or(0);
                    Err(match code {
                        -2 | -4 | -9 => "Touch ID geannuleerd".to_owned(),
                        -8 => "Touch ID is vergrendeld. Ontgrendel je Mac met je wachtwoord."
                            .to_owned(),
                        _ => "Touch ID is niet gelukt".to_owned(),
                    })
                };
                if let Some(tx) = tx.lock().unwrap().take() {
                    let _ = tx.send(result);
                }
                keep.lock().unwrap().take();
            });
            let text = NSString::from_str(reason);
            // DeviceOwnerAuthentication: Touch ID, with the account password as fallback.
            unsafe {
                context.evaluatePolicy_localizedReason_reply(
                    LAPolicy::DeviceOwnerAuthentication,
                    &text,
                    &reply,
                )
            };
            rx
        };
        rx.await
            .map_err(|_| CredError("Touch ID gaf geen antwoord".into()))?
            .map_err(CredError)
    }
}

#[cfg(target_os = "windows")]
mod win {
    use super::CredError;
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
    use windows::core::HSTRING;

    pub async fn confirm(reason: &str) -> Result<(), CredError> {
        let message = HSTRING::from(reason);
        let result = tokio::task::spawn_blocking(
            move || -> windows::core::Result<UserConsentVerificationResult> {
                UserConsentVerifier::RequestVerificationAsync(&message)?.join()
            },
        )
        .await
        .map_err(|e| CredError(e.to_string()))?
        .map_err(|e| CredError(format!("Windows Hello is niet gelukt: {e}")))?;
        match result {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::Canceled => {
                Err(CredError("Windows Hello geannuleerd".into()))
            }
            UserConsentVerificationResult::DeviceNotPresent
            | UserConsentVerificationResult::NotConfiguredForUser => Err(CredError(
                "Windows Hello staat niet aan op deze computer".into(),
            )),
            _ => Err(CredError("Windows Hello is niet gelukt".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Credentials, OpListError, OpReader, OpRequest, about_1password, batch_template,
        confirm_text, list_error, op_message, parse_items, plain_reference, split_batch,
        split_injected,
    };

    const LIST: &str = r#"[
      {"id":"itm1","title":"Zakelijke bank","version":3,"vault":{"id":"vlt1","name":"Werk"},"category":"LOGIN",
       "additional_information":"jan@studionoord.example","urls":[{"label":"website","primary":true,"href":"https://bank.example"}]},
      {"id":"itm2","title":"Studio Noord","vault":{"id":"vlt1","name":"Werk"},"category":"LOGIN",
       "additional_information":"jan@studionoord.example","urls":[{"primary":true,"href":"https://secure.e-Boekhouden.nl/bh/"}]},
      {"id":"itm3","title":"e-Boekhouden (Praktijk West)","vault":{"id":"vlt2","name":"Privé"},"category":"LOGIN"},
      {"id":"itm4","title":"agenda","vault":{"id":"vlt2","name":"Privé"},"category":"LOGIN","additional_information":"west"}
    ]"#;

    #[test]
    fn lists_e_boekhouden_items_first_by_their_ids() {
        let items = parse_items(LIST.as_bytes()).unwrap();
        let titles: Vec<&str> = items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "e-Boekhouden (Praktijk West)",
                "Studio Noord",
                "agenda",
                "Zakelijke bank"
            ]
        );
        assert!(items[0].suggested && items[1].suggested && !items[2].suggested);
        assert_eq!(items[1].reference, "op://vlt1/itm2");
        assert_eq!(items[1].vault, "Werk");
        assert_eq!(items[1].username, "jan@studionoord.example");
        assert_eq!(items[0].username, "");
    }

    #[test]
    fn reads_an_empty_list_and_refuses_garbage() {
        assert_eq!(parse_items(b"").unwrap(), vec![]);
        assert_eq!(parse_items(b" \n").unwrap(), vec![]);
        assert_eq!(parse_items(b"[]").unwrap(), vec![]);
        assert!(matches!(parse_items(b"{oops"), Err(OpListError::Other(_))));
    }

    #[test]
    fn tells_a_locked_1password_from_other_errors() {
        assert_eq!(
            list_error("[ERROR] authorization prompt dismissed, please try again"),
            OpListError::Locked
        );
        assert_eq!(
            list_error("[ERROR] You are not currently signed in."),
            OpListError::Locked
        );
        assert_eq!(
            list_error("[ERROR] 2026/11/10 12:00:00 something odd\n"),
            OpListError::Other(
                "1Password gaf geen lijst met items: 2026/11/10 12:00:00 something odd".into()
            )
        );
        let json = serde_json::to_string(&OpListError::Missing).unwrap();
        assert_eq!(json, r#"{"kind":"missing"}"#);
    }

    #[test]
    fn asks_for_touch_id_in_plain_dutch() {
        assert_eq!(
            confirm_text("Studio Noord"),
            "EB MCP wil het wachtwoord van Studio Noord gebruiken"
        );
    }

    /// The wait for `op`, tried with harmless commands.
    #[cfg(unix)]
    mod children {
        use crate::creds::{Waited, wait_child};
        use std::process::Command;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        #[test]
        fn kills_a_child_on_timeout_and_on_cancel() {
            let never = AtomicBool::new(false);
            let started = Instant::now();
            let waited = wait_child(
                Command::new("sleep").arg("30"),
                None,
                &|| never.load(Ordering::SeqCst),
                Instant::now() + Duration::from_millis(300),
            )
            .unwrap();
            assert!(matches!(waited, Waited::TimedOut), "{waited:?}");
            assert!(started.elapsed() < Duration::from_secs(5));

            let cancel = Arc::new(AtomicBool::new(false));
            let flag = cancel.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                flag.store(true, Ordering::SeqCst);
            });
            let started = Instant::now();
            let waited = wait_child(
                Command::new("sleep").arg("30"),
                None,
                &|| cancel.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(60),
            )
            .unwrap();
            assert!(matches!(waited, Waited::Cancelled), "{waited:?}");
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        #[test]
        fn returns_the_output_of_a_child_that_ends_in_time() {
            let never = AtomicBool::new(false);
            let waited = wait_child(
                Command::new("sh").args(["-c", "printf hallo; printf oeps >&2; exit 3"]),
                None,
                &|| never.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
            let Waited::Exited(output) = waited else {
                panic!("the child should have ended on its own")
            };
            assert_eq!(output.stdout, b"hallo");
            assert_eq!(output.stderr, b"oeps");
            assert_eq!(output.status.code(), Some(3));
            assert!(
                wait_child(
                    &mut Command::new("/nonexistent/op"),
                    None,
                    &|| never.load(Ordering::SeqCst),
                    Instant::now() + Duration::from_secs(1)
                )
                .is_err()
            );
            // What goes in on standard input comes out: how the template reaches `op inject`.
            let Waited::Exited(output) = wait_child(
                &mut Command::new("cat"),
                Some(b"een\ntwee"),
                &|| never.load(Ordering::SeqCst),
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap() else {
                panic!("cat should have ended at the end of its input")
            };
            assert_eq!(output.stdout, b"een\ntwee");
        }
    }

    #[test]
    fn one_start_of_op_reads_both_fields_of_a_reference_made_of_ids() {
        assert!(plain_reference("op://abcvault123/xyzitem456"));
        assert!(plain_reference("op://Werk/e-Boekhouden_1.2"));
        // A name with a space, or anything a template could read as its own syntax, is read field by field.
        assert!(!plain_reference("op://Werk/e-Boekhouden Studio Noord"));
        assert!(!plain_reference("op://Werk/a}}b"));
        assert!(!plain_reference("Werk/EB"));
        assert_eq!(
            split_injected("jan@studionoord.example\ngeheim\n"),
            Some(("jan@studionoord.example".into(), "geheim".into()))
        );
        // Without a line end after the password, with Windows line ends, and a password that ends in a space.
        assert_eq!(
            split_injected("jan\r\nge heim \r\n"),
            Some(("jan".into(), "ge heim ".into()))
        );
        assert_eq!(
            split_injected("jan\ngeheim"),
            Some(("jan".into(), "geheim".into()))
        );
        assert_eq!(split_injected("alleen een regel"), None);
    }

    #[test]
    fn one_template_asks_for_several_items_and_its_answer_is_split_per_item() {
        let template = batch_template(&["op://v1/i1", "op://v2/i2"], "--B--");
        assert_eq!(
            template,
            "--B--\n{{ op://v1/i1/username }}\n{{ op://v1/i1/password }}\n--B--\n{{ op://v2/i2/username }}\n{{ op://v2/i2/password }}\n--B--"
        );
        // What `op inject` writes for it: the same text with the references filled in.
        let output = "--B--\njan@studionoord.example\ngeheim\n--B--\nlisa\nw8 woord \n--B--\n";
        assert_eq!(
            split_batch(output, "--B--", 2),
            Some(vec![
                ("jan@studionoord.example".into(), "geheim".into()),
                ("lisa".into(), "w8 woord ".into())
            ])
        );
        assert_eq!(
            split_batch("--B--\r\njan\r\ngeheim\r\n--B--", "--B--", 1),
            Some(vec![("jan".into(), "geheim".into())])
        );
        // Fewer items than asked for, or no boundary at all: nothing is guessed.
        assert_eq!(split_batch(output, "--B--", 3), None);
        assert_eq!(split_batch("iets anders", "--B--", 1), None);
        // An empty field stays empty, for the caller to refuse.
        assert_eq!(
            split_batch("--B--\njan\n\n--B--", "--B--", 1),
            Some(vec![("jan".into(), String::new())])
        );
        assert!(about_1password("[ERROR] authorization prompt dismissed"));
        assert!(!about_1password(
            "[ERROR] \"EB\" isn't an item in the \"Werk\" vault"
        ));
    }

    /// Sign-ins that start together are read in one go; one that comes while a read runs waits for the next.
    #[tokio::test]
    async fn sign_ins_that_start_together_share_one_read() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        static SIZES: Mutex<Vec<usize>> = Mutex::new(Vec::new());
        static STARTS: AtomicUsize = AtomicUsize::new(0);
        fn fake(batch: Vec<OpRequest>) {
            STARTS.fetch_add(1, Ordering::SeqCst);
            SIZES.lock().unwrap().push(batch.len());
            std::thread::sleep(std::time::Duration::from_millis(150));
            let count = batch.len();
            for request in batch {
                let answer = if request.cancel.load(Ordering::SeqCst) {
                    Err(super::CredError("Inloggen gestopt".into()))
                } else {
                    Ok((
                        Credentials {
                            username: request.reference.clone(),
                            password: "geheim".into(),
                        },
                        count,
                    ))
                };
                let _ = request.answer.send(answer);
            }
        }
        let reader = Arc::new(OpReader::default());
        let go = Arc::new(AtomicBool::new(false));
        let read = |reference: &str| {
            let (reader, go, reference) = (reader.clone(), go.clone(), reference.to_owned());
            tokio::spawn(async move { reader.read_through(reference, &go, fake).await })
        };
        let first: Vec<_> = ["op://v/a", "op://v/b", "op://v/c"]
            .into_iter()
            .map(read)
            .collect();
        // While that read runs, two more come in: they wait and go together in the next one.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let later: Vec<_> = ["op://v/d", "op://v/e"].into_iter().map(read).collect();
        for (task, reference) in first.into_iter().zip(["op://v/a", "op://v/b", "op://v/c"]) {
            let (credentials, together) = task.await.unwrap().unwrap();
            assert_eq!((credentials.username.as_str(), together), (reference, 3));
        }
        for task in later {
            assert_eq!(task.await.unwrap().unwrap().1, 2);
        }
        assert_eq!(*SIZES.lock().unwrap(), [3, 2]);
        assert_eq!(STARTS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn explains_1password_errors_without_details() {
        let r = "op://Werk/EB";
        assert!(
            op_message("[ERROR] \"EB\" isn't an item in the \"Werk\" vault", r)
                .contains("vindt op://Werk/EB niet")
        );
        assert!(op_message("[ERROR] authorization prompt dismissed", r).contains("vergrendeld"));
        assert!(op_message("[ERROR] item does not have a field password", r).contains("geen veld"));
        assert_eq!(
            op_message("something odd: s3cr3t", r),
            "1Password gaf geen gegevens voor op://Werk/EB"
        );
    }
}
