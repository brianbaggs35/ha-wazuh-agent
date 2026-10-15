import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { effectScope } from 'vue'
import { usePoller } from './usePoller'

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('usePoller', () => {
  it('fetches at once, records the data and the time, and clears any error', async () => {
    const poller = usePoller(() => Promise.resolve({ n: 1 }), 1000)
    poller.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(poller.data.value).toEqual({ n: 1 })
    expect(poller.error.value).toBeNull()
    expect(poller.fetchedAt.value).toBeInstanceOf(Date)
    poller.stop()
  })

  it('fetches again after each interval', async () => {
    const fetcher = vi.fn().mockResolvedValue(1)
    const poller = usePoller(fetcher, 1000)
    poller.start()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(1000)
    await vi.advanceTimersByTimeAsync(1000)
    expect(fetcher).toHaveBeenCalledTimes(3)
    poller.stop()
  })

  it('keeps the last good data when a fetch fails, and carries on', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce('good')
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValue('good again')
    const poller = usePoller(fetcher, 1000)
    poller.start()
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(1000)
    expect(poller.data.value).toBe('good')
    expect(poller.error.value?.message).toBe('boom')
    await vi.advanceTimersByTimeAsync(1000)
    expect(poller.data.value).toBe('good again')
    expect(poller.error.value).toBeNull()
    poller.stop()
  })

  it('wraps something that is not an Error', async () => {
    const poller = usePoller(() => Promise.reject('plain text'), 1000)
    poller.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(poller.error.value).toBeInstanceOf(Error)
    expect(poller.error.value?.message).toBe('plain text')
    poller.stop()
  })

  it('starting twice does not double the polling', async () => {
    const fetcher = vi.fn().mockResolvedValue(1)
    const poller = usePoller(fetcher, 1000)
    poller.start()
    poller.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(fetcher).toHaveBeenCalledTimes(1)
    poller.stop()
  })

  it('stops for good, even when a fetch is still in flight', async () => {
    let finish!: (value: number) => void
    const fetcher = vi
      .fn()
      .mockImplementation(() => new Promise<number>((resolve) => (finish = resolve)))
    const poller = usePoller(fetcher, 1000)
    poller.start()
    poller.stop()
    finish(1)
    await vi.advanceTimersByTimeAsync(5000)
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('can be started again after a stop', async () => {
    const fetcher = vi.fn().mockResolvedValue(1)
    const poller = usePoller(fetcher, 1000)
    poller.start()
    await vi.advanceTimersByTimeAsync(0)
    poller.stop()
    poller.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(fetcher).toHaveBeenCalledTimes(2)
    poller.stop()
  })

  it('stops when its scope is disposed', async () => {
    const fetcher = vi.fn().mockResolvedValue(1)
    const scope = effectScope()
    const poller = scope.run(() => usePoller(fetcher, 1000))!
    poller.start()
    await vi.advanceTimersByTimeAsync(0)
    scope.stop()
    await vi.advanceTimersByTimeAsync(5000)
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})
