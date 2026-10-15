import { ref, watch } from 'vue'

export type ThemePreference = 'system' | 'light' | 'dark'

const key = 'wazuh-agent-theme'
const order: ThemePreference[] = ['system', 'light', 'dark']

function read(storage: Pick<Storage, 'getItem'>): ThemePreference {
  try {
    const stored = storage.getItem(key)
    return order.includes(stored as ThemePreference) ? (stored as ThemePreference) : 'system'
  } catch {
    return 'system' // storage can be blocked (private windows, embedded frames)
  }
}

/** The theme choice (follow the system, light or dark), remembered when storage allows it. */
export function useThemePreference(
  storage: Pick<Storage, 'getItem' | 'setItem'> = window.localStorage,
) {
  const preference = ref<ThemePreference>(read(storage))

  watch(preference, (value) => {
    try {
      storage.setItem(key, value)
    } catch {
      // Not remembering the choice is fine.
    }
  })

  function cycle(): void {
    preference.value = order[(order.indexOf(preference.value) + 1) % order.length]!
  }

  return { preference, cycle }
}
