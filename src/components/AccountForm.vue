<script setup lang="ts">
// Add or edit an account. Passwords go straight to the system store; the app keeps none.
import { computed, reactive, ref } from 'vue'
import { addAccount, KINDS, LEVEL_LABELS, presetOf, PRESETS, updateAccount, type AccountView, type Kind, type Level, type OpItem, type Rights, type StoreKind } from '../lib/accounts'
import { unlockName } from '../lib/server'
import Avatar from './Avatar.vue'
import Icon from './Icon.vue'
import OpItemPicker from './OpItemPicker.vue'
import Sheet from './Sheet.vue'

const props = defineProps<{ account?: AccountView }>()
const emit = defineEmits<{ close: []; saved: [AccountView, boolean]; remove: [AccountView] }>()

const editing = computed(() => !!props.account)
const form = reactive({
  label: props.account?.label ?? '',
  store: (props.account?.store ?? 'onePassword') as StoreKind,
  opRef: props.account?.opRef ?? '',
  opTitle: props.account?.opTitle ?? null as string | null,
  opVault: props.account?.opVault ?? null as string | null,
  username: props.account?.store === 'system' ? props.account.username : '',
  password: '',
  rights: { ...(props.account?.rights ?? PRESETS[0]!.rights) } as Rights,
})
/** The preset the four levels add up to, if any; set by hand they are an own choice. */
const preset = computed(() => presetOf(form.rights))

/** Whether the account has a session that stands, has one that expired, or none: the chip in the head. */
const session = computed(() => {
  const now = props.account?.session
  if (!now) return { tone: 'off', text: 'Niet ingelogd' }
  return now.expired ? { tone: 'bad', text: 'Sessie verlopen' } : { tone: 'on', text: 'Ingelogd' }
})
/** What Opslaan does besides saving, in one quiet line next to the buttons. */
const footNote = computed(() => {
  if (!props.account) return 'Opslaan logt één keer in om de gegevens te controleren en de administratienaam op te halen.'
  return session.value.tone === 'on' ? 'Wijzigingen gelden vanaf de volgende keer inloggen; de lopende sessie blijft.' : ''
})
const storeHint = computed(() =>
  form.store === 'onePassword'
    ? 'EB MCP bewaart alleen een op://-verwijzing en leest het item via de 1Password-CLI, alleen bij het inloggen. 1Password vraagt zelf om toestemming.'
    : `Gebruikersnaam en wachtwoord in je sleutelhanger, met ${unlockName} bij elk gebruik. EB MCP schrijft het wachtwoord nergens anders weg.`,
)
function setLevel(kind: Kind, level: Level) {
  form.rights[kind] = level
}
const error = ref<string | null>(null)
const busy = ref(false)
const showPassword = ref(false)

/** 1Password: the chosen item as a card, the list to pick from, or a reference typed by hand. */
type OpMode = 'card' | 'picker' | 'manual'
const opMode = ref<OpMode>(props.account?.opRef ? 'card' : 'picker')
/** The list asks 1Password for consent, so it only loads after a click. */
const pickerOpen = ref(false)

/** The username shown on the card: from the picked item, else the one read at the last sign-in. */
const pickedUser = ref<string | null>(props.account?.store === 'onePassword' ? props.account.username || null : null)
const cardSub = computed(() =>
  form.opTitle ? [form.opVault, pickedUser.value].filter(Boolean).join(' · ') || '1Password' : 'Zelf ingevulde verwijzing',
)

function pick(item: OpItem) {
  pickedUser.value = item.username || null
  form.opRef = item.reference
  form.opTitle = item.title || null
  form.opVault = item.vault || null
  if (!form.label.trim() && item.title) form.label = item.title.slice(0, 60)
  opMode.value = 'card'
  pickerOpen.value = false
}

function changeItem() {
  opMode.value = 'picker'
  pickerOpen.value = true
}

function closePicker() {
  pickerOpen.value = false
  if (form.opRef) opMode.value = 'card'
}

function typeByHand() {
  opMode.value = 'manual'
  pickerOpen.value = false
}

/** A reference typed by hand has no title or vault to show. */
function onManualInput() {
  form.opTitle = null
  form.opVault = null
}

async function save() {
  if (busy.value) return
  busy.value = true
  error.value = null
  const input = {
    label: form.label,
    username: form.store === 'system' ? form.username : (props.account?.username ?? ''),
    store: form.store,
    opRef: form.store === 'onePassword' ? form.opRef : null,
    opTitle: form.store === 'onePassword' ? form.opTitle : null,
    opVault: form.store === 'onePassword' ? form.opVault : null,
    rights: { ...form.rights },
  }
  try {
    const password = form.store === 'system' && form.password ? form.password : null
    const saved = props.account ? await updateAccount(props.account.id, input, password) : await addAccount(input, password)
    form.password = ''
    emit('saved', saved, !props.account)
  } catch (e) {
    error.value = String(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Sheet :title="editing ? `${account!.label} bewerken` : 'Account toevoegen'" :width="860" @close="emit('close')">
    <template #header>
      <div class="head">
        <Avatar :label="form.label || 'Nieuw account'" :size="40" :muted="!form.label.trim()" />
        <span class="head-text">
          <h2 class="head-title">{{ form.label.trim() || (editing ? account!.label : 'Account toevoegen') }}</h2>
          <span class="head-sub">{{ editing ? (account!.administration ? `Administratie ${account!.administration}` : 'De administratienaam volgt na de eerste keer inloggen') : 'Nieuw account bij e-Boekhouden' }}</span>
        </span>
        <span v-if="editing" class="state" :class="session.tone"><span class="state-dot" aria-hidden="true" />{{ session.text }}</span>
      </div>
    </template>
    <form id="account-form" class="form" @submit.prevent="save">
      <section class="col" aria-label="Inloggen bij e-Boekhouden">
        <h3 class="col-title">Inloggen bij e-Boekhouden</h3>
        <label class="field-block">
          <span class="label">Naam in EB MCP</span>
          <input v-model="form.label" class="field" maxlength="60" placeholder="Studio Noord" required />
        </label>
        <div class="field-block">
          <span class="label">Wachtwoord staat in</span>
          <div class="seg" role="radiogroup" aria-label="Wachtwoord bewaren in">
            <button type="button" role="radio" :aria-checked="form.store === 'onePassword'" :class="{ on: form.store === 'onePassword' }" @click="form.store = 'onePassword'">1Password</button>
            <button type="button" role="radio" :aria-checked="form.store === 'system'" :class="{ on: form.store === 'system' }" @click="form.store = 'system'">Sleutelhanger</button>
          </div>
          <span class="hint">{{ storeHint }}</span>
        </div>
        <Transition name="accordion" mode="out-in">
          <div v-if="form.store === 'onePassword'" key="onePassword" class="accordion fields">
            <div class="fields-inner">
              <div class="field-block">
                <span id="op-item-label" class="label">1Password-item</span>
                <Transition name="swap-op" mode="out-in">
                  <div v-if="opMode === 'card'" key="card" class="op-card" role="group" aria-labelledby="op-item-label">
                    <span class="op-icon"><Icon name="key" :size="16" /></span>
                    <span class="op-text">
                      <span class="op-title" :class="{ mono: !form.opTitle }" :title="form.opTitle ?? form.opRef">{{ form.opTitle ?? form.opRef }}</span>
                      <span class="op-sub" :title="cardSub">{{ cardSub }}</span>
                    </span>
                    <button type="button" class="btn small" @click="changeItem">Wijzigen</button>
                  </div>
                  <div v-else-if="opMode === 'picker'" key="picker" class="op-picker">
                    <Transition name="swap-op" mode="out-in">
                      <OpItemPicker v-if="pickerOpen" :current="form.opRef || null" @pick="pick" @close="closePicker" />
                      <button v-else type="button" class="btn op-choose" @click="pickerOpen = true"><Icon name="search" :size="15" />Kies uit 1Password…</button>
                    </Transition>
                  </div>
                  <input
                    v-else key="manual" v-model="form.opRef" class="field mono" placeholder="op://Werk/e-Boekhouden Studio Noord"
                    aria-labelledby="op-item-label" spellcheck="false" @input="onManualInput"
                  />
                </Transition>
                <span class="op-links">
                  <button v-if="opMode !== 'manual'" type="button" class="link" @click="typeByHand">Verwijzing zelf invullen</button>
                  <button v-else type="button" class="link" @click="changeItem">Kies uit de lijst</button>
                </span>
              </div>
            </div>
          </div>
          <div v-else key="system" class="accordion fields">
            <div class="fields-inner">
              <label class="field-block">
                <span class="label">Gebruikersnaam of e-mailadres</span>
                <input v-model="form.username" class="field" autocomplete="off" spellcheck="false" />
              </label>
              <label class="field-block">
                <span class="label">Wachtwoord</span>
                <span class="with-button">
                  <input v-model="form.password" class="field" :type="showPassword ? 'text' : 'password'" autocomplete="new-password" :placeholder="editing && account!.store === 'system' ? 'Leeg laten om het huidige te houden' : ''" />
                  <button type="button" class="btn small ghost" :aria-pressed="showPassword" @click="showPassword = !showPassword">{{ showPassword ? 'Verbergen' : 'Tonen' }}</button>
                </span>
              </label>
            </div>
          </div>
        </Transition>
      </section>

      <section class="col" aria-label="Wat AI-clients in dit account mogen">
        <span class="col-head">
          <h3 class="col-title">Wat AI-clients in dit account mogen</h3>
          <Transition name="swap-name" mode="out-in"><span :key="preset?.id ?? 'own'" class="preset-name">{{ preset?.label ?? 'Eigen instelling' }}</span></Transition>
        </span>
        <div class="tiles" role="radiogroup" aria-label="AI-clients mogen in dit account">
          <button v-for="p in PRESETS" :key="p.id" type="button" role="radio" :aria-checked="preset?.id === p.id" class="tile" :class="{ on: preset?.id === p.id }" @click="form.rights = { ...p.rights }">
            <strong>{{ p.label }}</strong><small>{{ p.hint }}</small>
          </button>
        </div>
        <div class="rights">
          <div v-for="k in KINDS" :key="k.kind" class="right" :class="{ off: form.rights[k.kind] === 'off' }">
            <span class="right-text">
              <span class="right-name">{{ k.label }}</span>
              <span class="hint">{{ k.hint }}</span>
            </span>
            <div class="seg small" role="radiogroup" :aria-label="k.label">
              <button v-for="level in k.levels" :key="level" type="button" role="radio" :aria-checked="form.rights[k.kind] === level" :class="{ on: form.rights[k.kind] === level, free: level === 'auto' }" @click="setLevel(k.kind, level)">{{ LEVEL_LABELS[level] }}</button>
            </div>
          </div>
        </div>
        <Transition name="accordion">
          <div v-if="form.rights.delete === 'auto'" class="accordion fields">
            <div class="fields-inner">
              <p class="note bad" role="status">Verwijderen zonder akkoord: een AI-client kan iets weghalen zonder dat jij het eerst ziet, en dat komt niet terug.</p>
            </div>
          </div>
        </Transition>
      </section>

      <Transition name="accordion">
        <div v-if="error" class="accordion wide"><div><p class="note bad" role="alert">{{ error }}</p></div></div>
      </Transition>
    </form>
    <template #footer>
      <span class="foot-start">
        <button v-if="editing" type="button" class="link danger" @click="emit('remove', account!)">Account verwijderen…</button>
        <span v-if="footNote" class="hint foot-note" :title="footNote">{{ footNote }}</span>
      </span>
      <button type="button" class="btn" @click="emit('close')">Annuleren</button>
      <button type="submit" form="account-form" class="btn primary" :disabled="busy" :aria-busy="busy"><span class="btn-label">Opslaan</span></button>
    </template>
  </Sheet>
</template>

<style scoped>
.head { flex: none; display: flex; align-items: center; gap: 12px; padding: 18px 20px 14px; }
.head-text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.head-title { font-size: 16px; line-height: 21px; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.head-sub { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.state { flex: none; height: 24px; display: inline-flex; align-items: center; gap: 6px; padding: 0 10px; border-radius: 999px; background: var(--subtle); color: var(--muted); font-size: 12px; font-weight: 500; }
.state-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.state.on { background: var(--success-soft); color: var(--success); }
.state.bad { background: var(--danger-soft); color: var(--danger); }
/* Two columns side by side: how EB MCP signs in, and what AI clients may do. In a window too narrow for both
   (the sheet under 700 px) they stack and the sheet scrolls. */
.form { container: account-form / inline-size; display: grid; grid-template-columns: minmax(0, 0.8fr) minmax(0, 1fr); align-items: start; border-top: 0.5px solid var(--line); margin-top: -12px; }
.col { min-width: 0; display: flex; flex-direction: column; gap: 14px; padding: 16px 0 14px; }
.col:first-child { padding-right: 20px; }
.col + .col { padding-left: 20px; border-left: 0.5px solid var(--line); align-self: stretch; }
.wide { grid-column: 1 / -1; }
.col-head { display: flex; align-items: baseline; gap: 8px; }
.col-title { font-size: 11px; font-weight: 600; color: var(--muted); }
.preset-name { margin-left: auto; font-size: 11px; color: var(--muted); }
.swap-name-enter-active, .swap-name-leave-active { transition: opacity 120ms ease; }
.swap-name-enter-from, .swap-name-leave-to { opacity: 0; }
.field-block { display: flex; flex-direction: column; gap: 6px; }
.label { font-size: 12px; font-weight: 600; color: var(--label); }
.field {
  box-sizing: border-box; width: 100%; height: 28px; padding: 0 10px; border: 0; border-radius: 8px; background: var(--field-bg);
  box-shadow: inset 0 0 0 0.5px var(--field); outline: none; transition: box-shadow 150ms ease; -webkit-user-select: text; user-select: text;
}
.field:focus { box-shadow: inset 0 0 0 1px var(--accent), 0 0 0 3.5px rgba(10, 132, 255, 0.42); }
.hint { font-size: 11px; line-height: 15px; color: var(--muted); }
.seg { align-self: flex-start; display: inline-flex; padding: 2px; border-radius: 999px; background: var(--subtle); }
.seg button { height: 24px; padding: 0 12px; border: 0; border-radius: 999px; background: transparent; font-size: 12px; white-space: nowrap; transition: background-color 180ms var(--ease), box-shadow 180ms var(--ease); }
.seg button:hover { background: var(--hover); }
.seg button.on { background: var(--seg-on); box-shadow: var(--seg-on-shadow); font-weight: 500; }
.seg.small { align-self: center; flex: none; }
.seg.small button { height: 22px; padding: 0 10px; font-size: 11.5px; transition: background-color 180ms var(--ease), box-shadow 180ms var(--ease), color 180ms var(--ease); }
.seg.small button.free.on { color: var(--danger); }
/* The usual choices as three tiles, each saying what it sets. */
.tiles { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.tile {
  display: flex; flex-direction: column; gap: 3px; align-items: flex-start; padding: 10px 11px; border: 0; border-radius: 11px; text-align: left;
  background: var(--group); box-shadow: inset 0 0 0 0.5px var(--line); transition: box-shadow 150ms ease, background-color 150ms ease;
}
.tile:hover { background: var(--hover); }
.tile.on, .tile.on:hover { background: var(--info-soft); box-shadow: inset 0 0 0 1.5px var(--accent); }
.tile strong { font-size: 12.5px; font-weight: 600; }
.tile small { font-size: 11px; line-height: 15px; color: var(--muted); }
.rights { display: flex; flex-direction: column; border-radius: 11px; background: var(--sunken); box-shadow: inset 0 0 0 0.5px var(--field); }
.right { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 9px 10px 9px 12px; }
.right + .right { box-shadow: inset 0 0.5px 0 var(--field); }
.right-text { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.right-name { font-size: 12.5px; font-weight: 500; transition: color 180ms var(--ease); }
.right.off .right-name { color: var(--label); }
.fields-inner { display: flex; flex-direction: column; gap: 14px; }
.fields.accordion-leave-active, .fields.accordion-leave-active > * { transition-duration: 120ms; }
.op-card { display: flex; align-items: center; gap: 10px; padding: 9px 10px; border-radius: 11px; background: var(--sunken); box-shadow: inset 0 0 0 0.5px var(--line); }
.op-icon { width: 30px; height: 30px; flex: none; border-radius: 9px; background: var(--info-soft); color: var(--info); display: flex; align-items: center; justify-content: center; }
.op-text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
.op-title, .op-sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.op-title { font-size: 13px; font-weight: 600; }
.op-sub { font-size: 11px; color: var(--muted); }
.op-choose { align-self: flex-start; }
.op-picker { display: flex; flex-direction: column; }
.op-links { display: flex; }
.link { padding: 0; border: 0; background: transparent; color: var(--accent); font-size: 12px; white-space: nowrap; text-decoration: underline; text-decoration-color: transparent; transition: text-decoration-color 150ms ease; }
.link:hover, .link:focus-visible { text-decoration-color: currentColor; }
.link.danger { color: var(--danger); }
.swap-op-enter-active { transition: opacity 180ms var(--ease), transform 180ms var(--ease); }
.swap-op-leave-active { transition: opacity 120ms cubic-bezier(0.4, 0, 1, 1); }
.swap-op-enter-from { opacity: 0; transform: translateY(-4px); }
.swap-op-leave-to { opacity: 0; }
.with-button { display: flex; gap: 6px; align-items: center; }
.note { padding: 9px 11px; border-radius: 10px; font-size: 12px; line-height: 16px; }
.note.bad { background: var(--danger-soft); color: var(--danger); }
.wide .note { margin-bottom: 8px; }
/* Verwijderen and the quiet line take the left of the foot; the two buttons keep their place on the right. */
.foot-start { flex: 1; min-width: 0; display: flex; align-items: center; gap: 14px; margin-right: 8px; }
.foot-note { min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
@container account-form (max-width: 700px) {
  .form { grid-template-columns: minmax(0, 1fr); }
  .col:first-child { padding-right: 0; }
  .col + .col { padding-left: 0; border-left: 0; border-top: 0.5px solid var(--line); }
}
@media (prefers-reduced-motion: reduce) { .swap-op-enter-from { transform: none; } }
</style>
