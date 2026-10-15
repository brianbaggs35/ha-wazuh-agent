import { describe, expect, it } from 'vitest'
import type { ConnectionResult } from '@/api/types'
import { makeStatus, now, summary } from '@/test/fixtures'
import { mountWithVuetify } from '@/test/mount'
import ConnectionCard from './ConnectionCard.vue'

type Status = ReturnType<typeof makeStatus>

function mountCard(
  status: Status | null,
  extra: { results?: ConnectionResult[] | null; testing?: boolean; testError?: Error | null } = {},
) {
  return mountWithVuetify(ConnectionCard, {
    props: { status, results: null, testing: false, testError: null, now, ...extra },
  })
}

const withStatus = (status: string): Status => makeStatus({ connection: { status } })

describe('ConnectionCard', () => {
  it('shows the manager and how recently the agent was heard from', () => {
    const wrapper = mountCard(makeStatus())
    expect(wrapper.text()).toContain('10.0.0.5:1514 TCP')
    expect(wrapper.find('[data-test="keepalive"]').text()).toBe('10 s ago')
    expect(wrapper.find('[data-test="ack"]').text()).toBe('9 s ago')
    expect(wrapper.text()).toContain('36')
  })

  it.each([
    ['connected', 'success'],
    ['disconnected', 'error'],
    ['pending', 'info'],
  ])('shows %s in the %s colour', (status, tone) => {
    const chip = mountCard(withStatus(status)).find('[data-test="status"]')
    expect(chip.text()).toBe(status)
    expect(chip.classes().join(' ')).toContain(tone)
  })

  it('says it is waiting before the agent reports', () => {
    const wrapper = mountCard(null)
    expect(wrapper.find('[data-test="status"]').text()).toBe('waiting')
    expect(wrapper.text()).toContain('never')
  })

  it('lists several managers, one per line', () => {
    const many = {
      ...summary,
      manager: { ...summary.manager, addresses: ['10.0.0.5', '10.0.0.6'] },
    }
    const text = mountCard(makeStatus({ summary: many })).text()
    expect(text).toContain('10.0.0.5:1514')
    expect(text).toContain('10.0.0.6:1514')
  })

  it('cannot test the connection without a manager', () => {
    expect(
      mountCard(makeStatus({ summary: undefined }))
        .find('[data-test="test"]')
        .attributes('disabled'),
    ).toBeDefined()
  })

  it('asks for a test when the button is pressed', async () => {
    const wrapper = mountCard(makeStatus())
    await wrapper.find('[data-test="test"]').trigger('click')
    expect(wrapper.emitted('test')).toHaveLength(1)
  })

  it('shows the button as busy while a test runs', () => {
    expect(
      mountCard(makeStatus(), { testing: true }).find('[data-test="test"]').classes().join(' '),
    ).toContain('loading')
  })

  it('shows the results of a test, one line each, with the reason for a failure', () => {
    const results: ConnectionResult[] = [
      {
        host: '10.0.0.5',
        port: 1514,
        purpose: 'events',
        tested: true,
        reachable: true,
        millis: 12,
      },
      {
        host: '10.0.0.5',
        port: 1515,
        purpose: 'enrollment',
        tested: true,
        reachable: false,
        note: 'connection refused',
      },
      {
        host: '10.0.0.6',
        port: 1514,
        purpose: 'events',
        tested: false,
        reachable: false,
        note: 'UDP cannot be tested',
      },
    ]
    const wrapper = mountCard(makeStatus(), { results })
    const chips = wrapper.findAll('[data-test="result"]').map((chip) => chip.text())
    expect(chips).toEqual(['reachable', 'unreachable', 'not tested'])
    expect(wrapper.text()).toContain('12 ms')
    expect(wrapper.text()).toContain('connection refused')
    expect(wrapper.text()).toContain('UDP cannot be tested')
  })

  it('says there is nothing to test when the list is empty', () => {
    expect(mountCard(makeStatus(), { results: [] }).find('[data-test="results"]').text()).toContain(
      'Nothing to test',
    )
  })

  it('shows why a test could not run', () => {
    const wrapper = mountCard(makeStatus(), {
      testError: new Error('The status service answered 500'),
    })
    expect(wrapper.find('[data-test="test-error"]').text()).toContain('500')
  })
})
