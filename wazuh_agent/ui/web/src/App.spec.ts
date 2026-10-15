import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { api } from '@/api/client'
import { createAppVuetify } from '@/plugins/vuetify'
import { makeStatus, makeUpdates } from '@/test/fixtures'
import App from './App.vue'

vi.mock('@/api/client', () => ({
  api: { status: vi.fn(), logs: vi.fn(), updates: vi.fn(), connectionTest: vi.fn() },
}))

const mocked = vi.mocked(api)

function mountApp() {
  const vuetify = createAppVuetify()
  const wrapper = mount(App, { global: { plugins: [vuetify] }, attachTo: document.body })
  return { wrapper, vuetify }
}

async function settle() {
  await vi.advanceTimersByTimeAsync(0)
  await flushPromises()
}

beforeEach(() => {
  vi.useFakeTimers()
  window.localStorage.clear()
  mocked.status.mockResolvedValue(makeStatus())
  mocked.logs.mockResolvedValue(['2026/10/15 11:00:00 wazuh-agentd: INFO: Started'])
  mocked.updates.mockResolvedValue(makeUpdates())
  mocked.connectionTest.mockResolvedValue([
    { host: '10.0.0.5', port: 1514, purpose: 'events', tested: true, reachable: true, millis: 3 },
  ])
})

afterEach(() => {
  document.body.innerHTML = ''
  vi.useRealTimers()
  vi.clearAllMocks()
})

describe('App', () => {
  it('asks for everything when it opens, and shows it', async () => {
    const { wrapper } = mountApp()
    await settle()
    expect(mocked.status).toHaveBeenCalledOnce()
    expect(mocked.logs).toHaveBeenCalledOnce()
    expect(mocked.updates).toHaveBeenCalledWith(false)
    expect(wrapper.find('[data-test="headline"]').text()).toBe('Running and connected')
    expect(wrapper.find('[data-test="registration"]').text()).toContain('001')
    expect(wrapper.find('[data-test="updates"]').text()).toContain('up to date')
    expect(wrapper.find('[data-test="log"]').text()).toContain('Started')
    expect(wrapper.find('[data-test="live"]').text()).toContain('Updated')
    wrapper.unmount()
  })

  it('keeps the status fresh every few seconds, and the log less often', async () => {
    const { wrapper } = mountApp()
    await settle()
    await vi.advanceTimersByTimeAsync(5000)
    expect(mocked.status).toHaveBeenCalledTimes(2)
    expect(mocked.logs).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(5000)
    expect(mocked.status).toHaveBeenCalledTimes(3)
    expect(mocked.logs).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('says it cannot reach the service when the status call fails', async () => {
    mocked.status.mockRejectedValue(new Error('The status service answered 502'))
    const { wrapper } = mountApp()
    await settle()
    expect(wrapper.find('[data-test="headline"]').text()).toBe('Status unavailable')
    expect(wrapper.find('[data-test="live"]').text()).toContain('Offline')
    wrapper.unmount()
  })

  it('checks for updates again when asked', async () => {
    const { wrapper } = mountApp()
    await settle()
    await wrapper.find('[data-test="refresh"]').trigger('click')
    await settle()
    expect(mocked.updates).toHaveBeenLastCalledWith(true)
    wrapper.unmount()
  })

  it('tests the connection when asked, and shows the result', async () => {
    const { wrapper } = mountApp()
    await settle()
    await wrapper.find('[data-test="test"]').trigger('click')
    await settle()
    expect(mocked.connectionTest).toHaveBeenCalledOnce()
    expect(wrapper.find('[data-test="results"]').text()).toContain('reachable')
    wrapper.unmount()
  })

  it('cycles the theme and remembers it', async () => {
    const { wrapper, vuetify } = mountApp()
    await settle()
    await wrapper.find('[data-test="theme"]').trigger('click') // system -> light
    await settle()
    expect(vuetify.theme.name.value).toBe('light')
    await wrapper.find('[data-test="theme"]').trigger('click') // light -> dark
    await settle()
    expect(vuetify.theme.name.value).toBe('dark')
    expect(window.localStorage.getItem('wazuh-agent-theme')).toBe('dark')
    wrapper.unmount()
  })

  it('keeps relative times moving once a second', async () => {
    const { wrapper } = mountApp()
    await settle()
    const before = wrapper.find('[data-test="keepalive"]').text()
    await vi.advanceTimersByTimeAsync(3000)
    expect(wrapper.find('[data-test="keepalive"]').text()).not.toBe('')
    expect(before).not.toBe('')
    wrapper.unmount()
  })

  it('stops its clock and its polling when it is closed', async () => {
    const clear = vi.spyOn(globalThis, 'clearInterval')
    const { wrapper } = mountApp()
    await settle()
    wrapper.unmount()
    expect(clear).toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(20000)
    expect(mocked.status).toHaveBeenCalledTimes(1)
  })
})
