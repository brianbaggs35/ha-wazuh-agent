import { describe, expect, it } from 'vitest'
import { makeStatus } from '@/test/fixtures'
import { mountWithVuetify } from '@/test/mount'
import ServicesCard from './ServicesCard.vue'

describe('ServicesCard', () => {
  it('lists each service in plain language, with its own name underneath', () => {
    const wrapper = mountWithVuetify(ServicesCard, { props: { status: makeStatus() } })
    const rows = wrapper.findAll('[data-test="daemon"]')
    expect(rows).toHaveLength(2)
    expect(rows[0]!.text()).toContain('Connection to the manager')
    expect(rows[0]!.text()).toContain('wazuh-agentd')
    expect(rows[0]!.text()).toContain('running')
  })

  it('tells a stopped service that should be running from one that is simply off', () => {
    const status = makeStatus({
      daemons: [
        { name: 'wazuh-agentd', running: true, expected: true },
        { name: 'wazuh-syscheckd', running: false, expected: true },
        { name: 'wazuh-execd', running: false, expected: false },
      ],
    })
    const text = mountWithVuetify(ServicesCard, { props: { status } })
      .findAll('[data-test="daemon"]')
      .map((row) => row.text())
    expect(text[1]).toContain('stopped')
    expect(text[2]).toContain('off')
  })

  it('says nothing has reported yet', () => {
    expect(
      mountWithVuetify(ServicesCard, { props: { status: makeStatus({ daemons: [] }) } })
        .find('[data-test="none"]')
        .exists(),
    ).toBe(true)
    expect(
      mountWithVuetify(ServicesCard, { props: { status: null } })
        .find('[data-test="none"]')
        .exists(),
    ).toBe(true)
  })
})
