import { getCurrentScope, onScopeDispose, ref, shallowRef } from 'vue'

/**
 * Calls `fetcher` now and then again `intervalMs` after each call finishes. A failed call keeps the
 * last good data and records the error, so a brief outage does not blank the page.
 */
export function usePoller<T>(fetcher: () => Promise<T>, intervalMs: number) {
  const data = shallowRef<T | null>(null)
  const error = ref<Error | null>(null)
  const fetchedAt = ref<Date | null>(null)
  let timer: ReturnType<typeof setTimeout> | undefined
  let running = false

  async function tick(): Promise<void> {
    try {
      data.value = await fetcher()
      error.value = null
      fetchedAt.value = new Date()
    } catch (caught) {
      error.value = caught instanceof Error ? caught : new Error(String(caught))
    }
    if (running) timer = setTimeout(tick, intervalMs)
  }

  function start(): void {
    if (running) return
    running = true
    void tick()
  }

  function stop(): void {
    running = false
    clearTimeout(timer)
  }

  if (getCurrentScope()) onScopeDispose(stop)
  return { data, error, fetchedAt, start, stop }
}
