import { describe, expect, it } from 'vitest'
import { makeStatus, summary } from '@/test/fixtures'
import { mountWithVuetify } from '@/test/mount'
import MonitoringCard from './MonitoringCard.vue'

const mountCard = (status: ReturnType<typeof makeStatus> | null) =>
  mountWithVuetify(MonitoringCard, { props: { status } })

describe('MonitoringCard', () => {
  it('lists what is on and what is off, in plain language', () => {
    const rows = mountCard(makeStatus()).findAll('[data-test="module"]')
    expect(rows).toHaveLength(5)
    const text = rows.map((row) => row.text())
    expect(text.find((line) => line.includes('Host journal'))).toContain('on')
    expect(text.find((line) => line.includes('Rootkit checks'))).toContain('off')
  })

  it('flags active response or remote commands that are switched on', () => {
    const risky = {
      ...summary,
      modules: { ...summary.modules, active_response: true, remote_commands: true },
    }
    const wrapper = mountCard(makeStatus({ summary: risky }))
    expect(wrapper.findAll('[data-test="caution"]')).toHaveLength(2)
  })

  it('does not flag them when they are off', () => {
    expect(mountCard(makeStatus()).find('[data-test="caution"]').exists()).toBe(false)
  })

  it('says the summary is not available yet', () => {
    expect(
      mountCard(makeStatus({ summary: undefined }))
        .find('[data-test="none"]')
        .exists(),
    ).toBe(true)
    expect(mountCard(null).find('[data-test="none"]').exists()).toBe(true)
  })
})
