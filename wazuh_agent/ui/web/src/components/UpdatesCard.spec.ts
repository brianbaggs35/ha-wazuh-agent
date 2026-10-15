import { describe, expect, it } from 'vitest'
import type { UpdateInfo } from '@/api/types'
import { makeUpdates, now } from '@/test/fixtures'
import { mountWithVuetify } from '@/test/mount'
import UpdatesCard from './UpdatesCard.vue'

function mountCard(info: UpdateInfo | null, extra: { busy?: boolean; error?: Error | null } = {}) {
  return mountWithVuetify(UpdatesCard, { props: { info, busy: false, error: null, now, ...extra } })
}

describe('UpdatesCard', () => {
  it('says it is checking before the first answer', () => {
    expect(mountCard(null).find('[data-test="loading"]').exists()).toBe(true)
  })

  it('says it is up to date', () => {
    const wrapper = mountCard(makeUpdates())
    expect(wrapper.find('[data-test="agent-chip"]').text()).toBe('up to date')
    expect(wrapper.find('[data-test="app-chip"]').text()).toBe('up to date')
    expect(wrapper.find('[data-test="agent-latest"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="checked"]').text()).toContain('5 min ago')
  })

  it('explains that a newer agent arrives as an update of the app', () => {
    const wrapper = mountCard(
      makeUpdates({ agent: { installed: '4.14.9', latest: '4.14.10', available: true } }),
    )
    expect(wrapper.find('[data-test="agent-chip"]').text()).toBe('update available')
    expect(wrapper.find('[data-test="agent-latest"]').text()).toBe('4.14.10')
    expect(wrapper.find('[data-test="agent-hint"]').text()).toContain('Settings → Apps')
  })

  it('tells the user to install an app update, and to mind the manager', () => {
    const wrapper = mountCard(
      makeUpdates({ app: { version: '1.0.0', latest: '1.1.0', available: true } }),
    )
    expect(wrapper.find('[data-test="app-latest"]').text()).toBe('1.1.0')
    expect(wrapper.find('[data-test="app-hint"]').text()).toContain('manager first')
    expect(wrapper.find('[data-test="agent-hint"]').exists()).toBe(false)
  })

  it('shows a failed agent check without alarm', () => {
    const wrapper = mountCard(
      makeUpdates({
        agent: { installed: '4.14.9', available: false, error: 'could not reach Wazuh' },
      }),
    )
    expect(wrapper.find('[data-test="agent-chip"]').text()).toBe('check failed')
    expect(wrapper.find('[data-test="agent-error"]').text()).toContain('could not reach Wazuh')
  })

  it('shows a failed app check', () => {
    const wrapper = mountCard(
      makeUpdates({ app: { available: false, error: 'the Supervisor answered 403' } }),
    )
    expect(wrapper.find('[data-test="app-error"]').text()).toBe('check failed')
    expect(wrapper.find('[data-test="app-error-text"]').text()).toContain('403')
    expect(wrapper.find('[data-test="app-version"]').text()).toBe('—')
  })

  it('leaves out the app row when the Supervisor was not asked', () => {
    const wrapper = mountCard(makeUpdates({ app: { available: false } }))
    expect(wrapper.find('[data-test="app-version"]').exists()).toBe(false)
  })

  it('shows a dash when the installed version is unknown', () => {
    const wrapper = mountCard(makeUpdates({ agent: { installed: '', available: false } }))
    expect(wrapper.find('[data-test="agent-installed"]').text()).toBe('—')
  })

  it('says update checks are off, and cannot be run', () => {
    const wrapper = mountCard({
      enabled: false,
      agent: { installed: '4.14.9', available: false },
      app: { available: false },
    })
    expect(wrapper.find('[data-test="disabled"]').text()).toContain('ui_update_check')
    expect(wrapper.find('[data-test="refresh"]').attributes('disabled')).toBeDefined()
  })

  it('shows why the check could not be made', () => {
    expect(
      mountCard(makeUpdates(), { error: new Error('offline') })
        .find('[data-test="error"]')
        .text(),
    ).toContain('offline')
  })

  it('asks for a fresh check when the button is pressed', async () => {
    const wrapper = mountCard(makeUpdates())
    await wrapper.find('[data-test="refresh"]').trigger('click')
    expect(wrapper.emitted('refresh')).toHaveLength(1)
  })

  it('shows the button as busy, and no check time before the first answer', () => {
    const wrapper = mountCard(null, { busy: true })
    expect(wrapper.find('[data-test="refresh"]').classes().join(' ')).toContain('loading')
    expect(wrapper.find('[data-test="checked"]').exists()).toBe(false)
  })
})
