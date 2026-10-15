import { getCurrentScope, onScopeDispose, ref, shallowRef } from 'vue'

/** A request the user starts (a button), with its result, its error and a busy flag. */
export function useAction<T, A extends unknown[]>(action: (...args: A) => Promise<T>) {
  const result = shallowRef<T | null>(null)
  const error = ref<Error | null>(null)
  const busy = ref(false)
  let disposed = false

  async function run(...args: A): Promise<void> {
    busy.value = true
    try {
      const value = await action(...args)
      if (!disposed) {
        result.value = value
        error.value = null
      }
    } catch (error_) {
      if (!disposed) error.value = error_ instanceof Error ? error_ : new Error(String(error_))
    } finally {
      if (!disposed) busy.value = false
    }
  }

  if (getCurrentScope()) {
    onScopeDispose(() => {
      disposed = true
    })
  }
  return { result, error, busy, run }
}
