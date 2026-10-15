import { describe, expect, it } from 'vitest'
import { createAppVuetify, darkTheme, lightTheme } from './vuetify'

describe('the Vuetify setup', () => {
  it('has a dark and a light palette with the same set of colours', () => {
    expect(darkTheme.dark).toBe(true)
    expect(lightTheme.dark).toBe(false)
    expect(Object.keys(darkTheme.colors!).sort()).toEqual(Object.keys(lightTheme.colors!).sort())
  })

  it('follows the system theme until the user chooses', () => {
    const vuetify = createAppVuetify()
    expect(vuetify.theme.name.value).toMatch(/^(light|dark|system)$/)
    expect(Object.keys(vuetify.theme.themes.value)).toEqual(
      expect.arrayContaining(['light', 'dark']),
    )
  })
})
