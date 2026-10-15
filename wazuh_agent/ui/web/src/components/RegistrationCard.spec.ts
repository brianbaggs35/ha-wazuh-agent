import { describe, expect, it } from 'vitest'
import { makeStatus, summary } from '@/test/fixtures'
import { mountWithVuetify } from '@/test/mount'
import RegistrationCard from './RegistrationCard.vue'

const mountCard = (status: ReturnType<typeof makeStatus> | null) =>
  mountWithVuetify(RegistrationCard, { props: { status } })

describe('RegistrationCard', () => {
  it('shows who the agent is registered as, and where to find it in Wazuh', () => {
    const wrapper = mountCard(makeStatus())
    expect(wrapper.find('[data-test="registered"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('001')
    expect(wrapper.find('[data-test="where"]').text()).toContain('homeassistant')
    expect(wrapper.text()).toContain('iot')
  })

  it('shows the security of the enrollment', () => {
    const wrapper = mountCard(makeStatus())
    expect(wrapper.find('[data-test="password"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="verified"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('1515')
  })

  it('leaves the security chips out when neither is configured', () => {
    const open = {
      ...summary,
      manager: {
        ...summary.manager,
        enrollment: { ...summary.manager.enrollment, password_set: false, verified: false },
      },
    }
    const wrapper = mountCard(makeStatus({ summary: open }))
    expect(wrapper.find('[data-test="password"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="verified"]').exists()).toBe(false)
  })

  it('says it is not registered yet', () => {
    const wrapper = mountCard(makeStatus({ registration: { registered: false } }))
    expect(wrapper.find('[data-test="unregistered"]').text()).toBe('Not registered yet')
    expect(wrapper.find('[data-test="where"]').exists()).toBe(false)
  })

  it('says why when enrollment is off', () => {
    const off = {
      ...summary,
      manager: {
        ...summary.manager,
        enrollment: { ...summary.manager.enrollment, enabled: false },
      },
    }
    const wrapper = mountCard(makeStatus({ registration: { registered: false }, summary: off }))
    expect(wrapper.find('[data-test="unregistered"]').text()).toContain('enrollment is off')
    expect(wrapper.text()).toContain('Off')
  })

  it('shows the default group when none is set', () => {
    const noGroups = { ...summary, agent: { ...summary.agent, groups: [] } }
    expect(mountCard(makeStatus({ summary: noGroups })).text()).toContain('default')
  })

  it('copes with having no status at all', () => {
    const wrapper = mountCard(null)
    expect(wrapper.find('[data-test="unregistered"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('—')
  })

  it('uses the name from the summary when the registration has none', () => {
    const wrapper = mountCard(makeStatus({ registration: { registered: false } }))
    expect(wrapper.text()).toContain('homeassistant')
  })

  it('shows a dash for a missing config profile', () => {
    const none = { ...summary, agent: { ...summary.agent, config_profile: '' } }
    expect(mountCard(makeStatus({ summary: none })).text()).toContain('—')
  })
})
