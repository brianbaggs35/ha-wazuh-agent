import { describe, expect, it } from 'vitest'
import { makeStatus, summary } from '@/test/fixtures'
import { mountWithVuetify } from '@/test/mount'
import HostCard from './HostCard.vue'

const mountCard = (status: ReturnType<typeof makeStatus> | null) =>
  mountWithVuetify(HostCard, { props: { status } })

describe('HostCard', () => {
  it('shows what Home Assistant reported about the device', () => {
    const wrapper = mountCard(makeStatus())
    const text = wrapper.text()
    expect(text).toContain('Home Assistant OS 16.2')
    expect(text).toContain('2026.10.1')
    expect(text).toContain('rpi4-64')
    expect(wrapper.findAll('[data-test="row"]')).toHaveLength(6)
  })

  it('says whether the agent watches the device or only its own container', () => {
    const device = {
      ...summary,
      host: { ...summary.host, scope: 'host', hostname: 'homeassistant' },
    }
    const text = mountCard(makeStatus({ summary: device })).text()
    expect(text).toContain('The Home Assistant OS device')
    expect(text).toContain('homeassistant')
    const own = { ...summary, host: { ...summary.host, scope: 'container' } }
    expect(mountCard(makeStatus({ summary: own })).text()).toContain(
      "This app's own container only",
    )
  })

  it('leaves out what was not reported', () => {
    const partial = {
      ...summary,
      host: { operating_system: 'Home Assistant OS 16.2', core_version: null, arch: '' },
    }
    expect(mountCard(makeStatus({ summary: partial })).findAll('[data-test="row"]')).toHaveLength(1)
  })

  it('says when nothing was reported', () => {
    expect(
      mountCard(makeStatus({ summary: undefined }))
        .find('[data-test="none"]')
        .exists(),
    ).toBe(true)
    expect(mountCard(null).find('[data-test="none"]').exists()).toBe(true)
  })
})
