import { describe, expect, it } from 'vitest'
import { now } from '@/test/fixtures'
import { mountInApp } from '@/test/mount'
import AppHeader from './AppHeader.vue'

const base = { fetchedAt: new Date('2026-10-15T11:59:50Z'), offline: false, now, theme: 'system' }

describe('AppHeader', () => {
  it('names the app', () => {
    const wrapper = mountInApp(AppHeader, base)
    expect(wrapper.text()).toContain('Wazuh Agent')
    expect(wrapper.text()).toContain('Home Assistant app')
  })

  it('shows when the status was last refreshed', () => {
    expect(mountInApp(AppHeader, base).find('[data-test="live"]').text()).toContain(
      'Updated 10 s ago',
    )
  })

  it('says so while it has not heard back yet', () => {
    const wrapper = mountInApp(AppHeader, { ...base, fetchedAt: null })
    expect(wrapper.find('[data-test="live"]').text()).toContain('Connecting')
  })

  it('says Offline, in the error colour, when the service cannot be reached', () => {
    const live = mountInApp(AppHeader, { ...base, offline: true }).find('[data-test="live"]')
    expect(live.text()).toContain('Offline')
    expect(live.classes().join(' ')).toContain('error')
  })

  it.each(['system', 'light', 'dark'])('labels the theme button for the %s theme', (theme) => {
    const button = mountInApp(AppHeader, { ...base, theme }).find('[data-test="theme"]')
    expect(button.attributes('aria-label')).toContain(theme)
  })

  it('asks to change the theme when the button is clicked', async () => {
    const wrapper = mountInApp(AppHeader, base)
    await wrapper.find('[data-test="theme"]').trigger('click')
    expect(wrapper.findComponent(AppHeader).emitted('cycle-theme')).toHaveLength(1)
  })
})
