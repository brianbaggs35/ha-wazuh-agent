import { describe, expect, it } from 'vitest'
import { effectScope } from 'vue'
import { useAction } from './useAction'

describe('useAction', () => {
  it('runs the action with its arguments and keeps the result', async () => {
    const action = useAction((a: number, b: number) => Promise.resolve(a + b))
    const pending = action.run(2, 3)
    expect(action.busy.value).toBe(true)
    await pending
    expect(action.result.value).toBe(5)
    expect(action.error.value).toBeNull()
    expect(action.busy.value).toBe(false)
  })

  it('records a failure, and a later success clears it', async () => {
    let fail = true
    const action = useAction(() =>
      fail ? Promise.reject(new Error('no')) : Promise.resolve('yes'),
    )
    await action.run()
    expect(action.error.value?.message).toBe('no')
    expect(action.busy.value).toBe(false)
    fail = false
    await action.run()
    expect(action.error.value).toBeNull()
    expect(action.result.value).toBe('yes')
  })

  it('wraps something that is not an Error', async () => {
    const action = useAction(() => Promise.reject('plain'))
    await action.run()
    expect(action.error.value?.message).toBe('plain')
  })

  it('does not touch its state after its scope is gone', async () => {
    const scope = effectScope()
    let finish!: (value: string) => void
    const action = scope.run(() =>
      useAction(() => new Promise<string>((resolve) => (finish = resolve))),
    )!
    const pending = action.run()
    scope.stop()
    finish('late')
    await pending
    expect(action.result.value).toBeNull()
    expect(action.busy.value).toBe(true)
  })

  it('does not record a failure after its scope is gone', async () => {
    const scope = effectScope()
    let fail!: (reason: Error) => void
    const action = scope.run(() =>
      useAction(() => new Promise<string>((_, reject) => (fail = reject))),
    )!
    const pending = action.run()
    scope.stop()
    fail(new Error('late'))
    await pending
    expect(action.error.value).toBeNull()
  })
})
