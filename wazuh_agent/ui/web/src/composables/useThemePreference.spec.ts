import { describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import { useThemePreference } from './useThemePreference'

function storage(initial: string | null = null) {
  const values = new Map<string, string>()
  if (initial !== null) values.set('wazuh-agent-theme', initial)
  return {
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => void values.set(key, value)),
  }
}

describe('useThemePreference', () => {
  it('follows the system by default', () => {
    expect(useThemePreference(storage()).preference.value).toBe('system')
  })

  it('restores a remembered choice', () => {
    expect(useThemePreference(storage('dark')).preference.value).toBe('dark')
  })

  it('ignores a remembered value it does not know', () => {
    expect(useThemePreference(storage('purple')).preference.value).toBe('system')
  })

  it('follows the system when storage is blocked', () => {
    const blocked = {
      getItem: () => {
        throw new Error('blocked')
      },
      setItem: vi.fn(),
    }
    expect(useThemePreference(blocked).preference.value).toBe('system')
  })

  it('cycles system, light, dark and back, remembering each', async () => {
    const store = storage()
    const theme = useThemePreference(store)
    const seen: string[] = []
    for (let i = 0; i < 4; i++) {
      theme.cycle()
      await nextTick()
      seen.push(theme.preference.value)
    }
    expect(seen).toEqual(['light', 'dark', 'system', 'light'])
    expect(store.setItem).toHaveBeenLastCalledWith('wazuh-agent-theme', 'light')
  })

  it('carries on when the choice cannot be remembered', async () => {
    const store = {
      getItem: () => null,
      setItem: () => {
        throw new Error('full')
      },
    }
    const theme = useThemePreference(store)
    theme.cycle()
    await nextTick()
    expect(theme.preference.value).toBe('light')
  })

  it('uses the browser storage by default', () => {
    window.localStorage.setItem('wazuh-agent-theme', 'light')
    expect(useThemePreference().preference.value).toBe('light')
    window.localStorage.clear()
  })
})
