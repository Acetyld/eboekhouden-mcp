import { describe, expect, it } from 'vitest'
import { dayBars, dayStart, hourBars, periodSince, type Minute } from '../lib/log'

const HOUR = 3_600_000
/** Thursday 12 November 2026, 15:20 in the time of whoever runs the test. */
const now = new Date(2026, 10, 12, 15, 20).getTime()
const counts = (eb: number, mcp = 0, errors = 0): Minute => ({ eb, mcp, errors })
const hourOf = (...at: [number, number, number, number]) => Math.floor(new Date(...at).getTime() / HOUR)

describe('dashboard periods', () => {
  it('starts today at midnight, seven days six midnights earlier, and everything nowhere', () => {
    expect(dayStart(now)).toBe(new Date(2026, 10, 12).getTime())
    expect(periodSince('today', now)).toBe(hourOf(2026, 10, 12, 0))
    expect(periodSince('week', now)).toBe(hourOf(2026, 10, 6, 0))
    expect(periodSince('all', now)).toBeUndefined()
  })

  it('draws the 24 hours of today, empty ones included', () => {
    const bars = hourBars([[hourOf(2026, 10, 11, 23), counts(9)], [hourOf(2026, 10, 12, 0), counts(1)], [hourOf(2026, 10, 12, 14), counts(4, 2, 1)]], now)
    expect(bars).toHaveLength(24)
    expect(bars[0]).toMatchObject({ label: '00:00 tot 01:00', m: counts(1) })
    expect(bars[14]!.m).toEqual(counts(4, 2, 1))
    // Yesterday's last hour is not today's.
    expect(bars.reduce((n, b) => n + b.m.eb, 0)).toBe(5)
  })

  it('sums the hours of each of the last seven days, today last', () => {
    const bars = dayBars(
      [[hourOf(2026, 10, 5, 23), counts(100)], [hourOf(2026, 10, 6, 0), counts(1)], [hourOf(2026, 10, 6, 23), counts(2, 1)], [hourOf(2026, 10, 12, 9), counts(3, 0, 1)], [hourOf(2026, 10, 12, 15), counts(4)]],
      now,
    )
    expect(bars).toHaveLength(7)
    expect(bars[0]!.m).toEqual(counts(3, 1))
    expect(bars[6]!.m).toEqual(counts(7, 0, 1))
    expect(bars[6]!.label).toBe('donderdag 12 november')
    // The day before the seven is left out.
    expect(bars.reduce((n, b) => n + b.m.eb, 0)).toBe(10)
  })
})
