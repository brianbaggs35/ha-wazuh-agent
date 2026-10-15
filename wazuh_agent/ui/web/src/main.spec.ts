import { describe, expect, it, vi } from 'vitest'

vi.mock('./App.vue', async () => {
  const { h } = await import('vue')
  return { default: { render: () => h('div', { 'data-test': 'app' }, 'mounted') } }
})

describe('main', () => {
  it('mounts the app into #app', async () => {
    document.body.innerHTML = '<div id="app"></div>'
    await import('./main')
    expect(document.querySelector('#app [data-test="app"]')?.textContent).toBe('mounted')
  })
})
