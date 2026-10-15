import { describe, expect, it } from 'vitest'
import { timeAgo } from './time'

const now = new Date('2026-10-15T12:00:00Z')
const ago = (seconds: number) => new Date(now.getTime() - seconds * 1000).toISOString()

describe('timeAgo', () => {
  it.each([
    [undefined, 'never'],
    ['', 'never'],
    ['not a date', 'unknown'],
    [ago(0), 'just now'],
    [ago(4), 'just now'],
    [ago(5), '5 s ago'],
    [ago(59), '59 s ago'],
    [ago(60), '1 min ago'],
    [ago(150), '3 min ago'],
    [ago(3300), '55 min ago'],
    [ago(3599), '1 h ago'],
    [ago(3 * 3600), '3 h ago'],
    [ago(47 * 3600), '47 h ago'],
    [ago(72 * 3600), '3 d ago'],
  ])('%s -> %s', (iso, expected) => {
    expect(timeAgo(iso, now)).toBe(expected)
  })
})
