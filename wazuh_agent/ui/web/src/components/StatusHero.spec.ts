import { describe, expect, it } from 'vitest'
import type { StateName } from '@/api/types'
import { makeStatus, summary } from '@/test/fixtures'
import { mountWithVuetify } from '@/test/mount'
import { stateLook } from '@/utils/labels'
import StatusHero from './StatusHero.vue'

const mountHero = (status: ReturnType<typeof makeStatus> | null, error: Error | null = null) =>
  mountWithVuetify(StatusHero, { props: { status, error } })

describe('StatusHero', () => {
  it('shows the headline and the sentence the service gives for the state', () => {
    const wrapper = mountHero(makeStatus())
    expect(wrapper.find('[data-test="headline"]').text()).toBe('Running and connected')
    expect(wrapper.find('[data-test="detail"]').text()).toContain('sending events')
  })

  it('shows the key facts', () => {
    const text = mountHero(makeStatus()).text()
    expect(text).toContain('homeassistant')
    expect(text).toContain('001')
    expect(text).toContain('10.0.0.5:1514 (TCP)')
    expect(text).toContain('4.14.9')
  })

  it.each(Object.keys(stateLook) as StateName[])(
    'draws the %s state in its own colour and icon',
    (state) => {
      const look = stateLook[state]
      const wrapper = mountHero(makeStatus({ state, headline: `H ${state}`, detail: `D ${state}` }))
      expect(wrapper.find('[data-test="headline"]').text()).toBe(`H ${state}`)
      expect(wrapper.find('[data-test="hero"]').attributes('style')).toContain(
        `--v-theme-${look.tone}`,
      )
      expect(wrapper.find('.hero-ring').classes().includes('hero-ring--pulse')).toBe(look.pulse)
    },
  )

  it('says it is loading before the first answer', () => {
    const wrapper = mountHero(null)
    expect(wrapper.find('[data-test="headline"]').text()).toBe('Loading')
    expect(wrapper.text()).toContain('—')
  })

  it('says the status is unavailable when the service cannot be reached', () => {
    const wrapper = mountHero(null, new Error('down'))
    expect(wrapper.find('[data-test="headline"]').text()).toBe('Status unavailable')
    expect(wrapper.find('[data-test="detail"]').text()).toContain('restart it')
    expect(wrapper.find('[data-test="hero"]').attributes('style')).toContain('--v-theme-error')
  })

  it('has fallbacks for a status without a summary or an identity', () => {
    const wrapper = mountHero(
      makeStatus({ summary: undefined, registration: { registered: false } }),
    )
    expect(wrapper.text()).toContain('not registered yet')
    expect(wrapper.text()).toContain('—')
  })

  it('falls back to the registered name when the summary has none', () => {
    const noName = { ...summary, agent: { ...summary.agent, name: '' } }
    const wrapper = mountHero(
      makeStatus({
        summary: noName,
        registration: { registered: true, id: '002', name: 'from-keys' },
      }),
    )
    expect(wrapper.text()).toContain('from-keys')
  })

  it('says "not set" when no manager address is configured', () => {
    const none = { ...summary, manager: { ...summary.manager, addresses: [] } }
    expect(mountHero(makeStatus({ summary: none })).text()).toContain('not set:1514')
  })

  it('shows a dash for a missing Wazuh version', () => {
    const noVersion = { ...summary, agent: { ...summary.agent, version: '' } }
    expect(mountHero(makeStatus({ summary: noVersion })).text()).toContain('—')
  })
})
