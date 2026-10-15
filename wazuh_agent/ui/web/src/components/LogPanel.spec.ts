import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountWithVuetify } from '@/test/mount'
import LogPanel from './LogPanel.vue'

const lines = [
  '2026/10/15 11:00:00 wazuh-agentd: INFO: Started',
  '2026/10/15 11:00:01 wazuh-logcollector: WARNING: file missing',
  '2026/10/15 11:00:02 wazuh-agentd: ERROR: Duplicate agent name',
  '2026/10/15 11:00:03 wazuh-syscheckd: CRITICAL: bad thing',
]

const mountLog = (props: { lines?: string[]; error?: Error | null } = {}) =>
  mountWithVuetify(LogPanel, { props: { lines, error: null, ...props }, attachTo: document.body })

// Replace only the clipboard: Vuetify reads the rest of `navigator` (the user agent) at start-up.
function setClipboard(writeText: () => Promise<void>) {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
}

afterEach(() => {
  document.body.innerHTML = ''
  vi.useRealTimers()
  Reflect.deleteProperty(navigator, 'clipboard')
})

describe('LogPanel', () => {
  it('shows every line, colouring warnings and errors', () => {
    const rendered = mountLog().findAll('[data-test="line"]')
    expect(rendered).toHaveLength(4)
    expect(rendered.map((line) => line.classes()[0])).toEqual([
      'log-info',
      'log-warning',
      'log-error',
      'log-error',
    ])
  })

  it('can show only warnings and errors', async () => {
    const wrapper = mountLog()
    await wrapper.find('[data-test="filter-issues"]').trigger('click')
    expect(wrapper.findAll('[data-test="line"]')).toHaveLength(3)
    await wrapper.find('[data-test="filter-all"]').trigger('click')
    expect(wrapper.findAll('[data-test="line"]')).toHaveLength(4)
  })

  it('says so when the filter hides everything', async () => {
    const wrapper = mountLog({ lines: [lines[0]!] })
    await wrapper.find('[data-test="filter-issues"]').trigger('click')
    expect(wrapper.find('[data-test="empty"]').text()).toContain('No warnings or errors')
  })

  it('says so when the log is empty', () => {
    expect(mountLog({ lines: [] }).find('[data-test="empty"]').text()).toBe('The log is empty.')
  })

  it('shows why the log could not be refreshed', () => {
    expect(
      mountLog({ error: new Error('down') })
        .find('[data-test="error"]')
        .text(),
    ).toContain('down')
  })

  describe('following the log', () => {
    async function scrollable(wrapper: ReturnType<typeof mountLog>) {
      const terminal = wrapper.find('[data-test="terminal"]').element as HTMLElement
      Object.defineProperty(terminal, 'scrollHeight', { value: 500, configurable: true })
      return terminal
    }

    it('scrolls to the newest line when new lines arrive', async () => {
      const wrapper = mountLog()
      const terminal = await scrollable(wrapper)
      await wrapper.setProps({ lines: [...lines, 'a new line'] })
      await flushPromises()
      expect(terminal.scrollTop).toBe(500)
    })

    it('stays where it is when Follow is switched off', async () => {
      const wrapper = mountLog()
      const terminal = await scrollable(wrapper)
      await wrapper.find('[data-test="follow"] input').setValue(false)
      await wrapper.setProps({ lines: [...lines, 'a new line'] })
      await flushPromises()
      expect(terminal.scrollTop).toBe(0)
    })

    it('copes with the panel going away before the scroll happens', async () => {
      const wrapper = mountLog()
      await wrapper.setProps({ lines: [...lines, 'a new line'] })
      wrapper.unmount()
      await flushPromises()
    })
  })

  describe('copying', () => {
    it('copies the lines that are shown, and says so for a moment', async () => {
      vi.useFakeTimers()
      const writeText = vi.fn().mockResolvedValue(undefined)
      setClipboard(writeText)
      const wrapper = mountLog()
      await wrapper.find('[data-test="filter-issues"]').trigger('click')
      await wrapper.find('[data-test="copy"]').trigger('click')
      await flushPromises()
      expect(writeText).toHaveBeenCalledWith(lines.slice(1).join('\n'))
      expect(wrapper.find('[data-test="copy"]').text()).toBe('Copied')
      await vi.advanceTimersByTimeAsync(2100)
      expect(wrapper.find('[data-test="copy"]').text()).toBe('Copy')
    })

    it('carries on when the clipboard is not available', async () => {
      setClipboard(vi.fn().mockRejectedValue(new Error('denied')))
      const wrapper = mountLog()
      await wrapper.find('[data-test="copy"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-test="copy"]').text()).toBe('Copy')
    })
  })
})

beforeEach(() => {
  document.body.innerHTML = ''
})
