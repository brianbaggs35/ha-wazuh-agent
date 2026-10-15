import 'vuetify/styles'
import { createVuetify, type ThemeDefinition } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi-svg'

// A teal-on-slate "console" palette. Dark is the natural home of a status page that sits next to
// Home Assistant's own dark UI; light is there for people who run it that way.
export const lightTheme: ThemeDefinition = {
  dark: false,
  colors: {
    background: '#f2f6fb',
    surface: '#ffffff',
    'surface-variant': '#e6edf7',
    primary: '#0f766e',
    secondary: '#475569',
    success: '#15803d',
    warning: '#b45309',
    error: '#be123c',
    info: '#0369a1',
  },
}

export const darkTheme: ThemeDefinition = {
  dark: true,
  colors: {
    background: '#0a101c',
    surface: '#111a2c',
    'surface-variant': '#1b2742',
    primary: '#2dd4bf',
    secondary: '#94a3b8',
    success: '#34d399',
    warning: '#fbbf24',
    error: '#fb7185',
    info: '#38bdf8',
  },
}

export function createAppVuetify() {
  return createVuetify({
    theme: { defaultTheme: 'system', themes: { light: lightTheme, dark: darkTheme } },
    icons: { defaultSet: 'mdi', aliases, sets: { mdi } },
    defaults: {
      VCard: { rounded: 'lg', flat: true },
      VBtn: { variant: 'tonal', rounded: 'lg' },
      VChip: { size: 'small', variant: 'tonal' },
    },
  })
}
