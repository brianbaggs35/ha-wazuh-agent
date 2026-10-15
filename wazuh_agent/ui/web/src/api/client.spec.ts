import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, apiUrl, getJson } from './client'

function respond(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return vi.fn().mockResolvedValue({
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  })
}

afterEach(() => vi.unstubAllGlobals())

describe('apiUrl', () => {
  it('is relative to the page, which Home Assistant serves under an ingress path', () => {
    const page = { href: 'https://ha.local/api/hassio_ingress/abc123/' }
    expect(apiUrl('status', page)).toBe('https://ha.local/api/hassio_ingress/abc123/api/status')
  })

  it('copes with a page address that lacks the trailing slash', () => {
    const page = { href: 'https://ha.local/api/hassio_ingress/abc123' }
    expect(apiUrl('status', page)).toBe('https://ha.local/api/hassio_ingress/abc123/api/status')
  })

  it('drops the query and the fragment of the page', () => {
    const page = { href: 'https://ha.local/x/?theme=dark#top' }
    expect(apiUrl('updates?refresh=1', page)).toBe('https://ha.local/x/api/updates?refresh=1')
  })

  it('uses the current location by default', () => {
    expect(apiUrl('status')).toMatch(/\/api\/status$/)
  })
})

describe('getJson', () => {
  it('asks for JSON without caching and returns the body', async () => {
    const fetcher = respond({ ok: 1 })
    await expect(getJson('status', fetcher as unknown as typeof fetch)).resolves.toEqual({ ok: 1 })
    const [url, init] = fetcher.mock.calls[0]!
    expect(url).toMatch(/\/api\/status$/)
    expect(init).toMatchObject({ headers: { Accept: 'application/json' }, cache: 'no-store' })
  })

  it('turns an error status into an ApiError that carries the status', async () => {
    const fetcher = respond({}, { ok: false, status: 403 })
    const error = (await getJson('status', fetcher as unknown as typeof fetch).catch(
      (caught: unknown) => caught,
    )) as ApiError
    expect(error).toBeInstanceOf(ApiError)
    expect(error.status).toBe(403)
    expect(error.message).toContain('403')
    expect(error.name).toBe('ApiError')
  })

  it('uses the global fetch by default', async () => {
    const fetcher = respond({ hello: 'world' })
    vi.stubGlobal('fetch', fetcher)
    await expect(getJson('status')).resolves.toEqual({ hello: 'world' })
    expect(fetcher).toHaveBeenCalledOnce()
  })
})

describe('api', () => {
  it('status', async () => {
    vi.stubGlobal('fetch', respond({ state: 'running' }))
    await expect(api.status()).resolves.toEqual({ state: 'running' })
  })

  it('updates, with and without a refresh', async () => {
    const fetcher = respond({ enabled: true })
    vi.stubGlobal('fetch', fetcher)
    await api.updates()
    await api.updates(true)
    expect(fetcher.mock.calls[0]![0]).toMatch(/api\/updates$/)
    expect(fetcher.mock.calls[1]![0]).toMatch(/api\/updates\?refresh=1$/)
  })

  it('logs unwraps the lines', async () => {
    vi.stubGlobal('fetch', respond({ lines: ['a', 'b'] }))
    await expect(api.logs()).resolves.toEqual(['a', 'b'])
  })

  it('connectionTest unwraps the results', async () => {
    vi.stubGlobal('fetch', respond({ results: [{ host: 'm' }] }))
    await expect(api.connectionTest()).resolves.toEqual([{ host: 'm' }])
  })
})
