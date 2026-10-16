import { describe, expect, it } from 'vitest'
import type { StateName } from '@/api/types'
import { daemonLabel, moduleLabel, riskyWhenOn, scopeLabel, stateLook } from './labels'

const states: StateName[] = [
  'starting',
  'stale',
  'stopped',
  'degraded',
  'disconnected',
  'connecting',
  'running',
  'needs_host_access',
]

describe('stateLook', () => {
  it('has a look for every state the service can report', () => {
    for (const state of states) {
      expect(stateLook[state], state).toBeDefined()
      expect(stateLook[state].icon.length).toBeGreaterThan(10)
    }
    expect(Object.keys(stateLook).sort()).toEqual([...states].sort())
  })

  it('shows trouble in a warning or error colour and health in success', () => {
    expect(stateLook.running.tone).toBe('success')
    expect(stateLook.degraded.tone).toBe('warning')
    expect(stateLook.stopped.tone).toBe('error')
    expect(stateLook.disconnected.tone).toBe('error')
    expect(stateLook.needs_host_access.tone).toBe('warning')
  })
})

describe('scopeLabel', () => {
  it('says in words where the agent runs, and leaves anything else as it is', () => {
    expect(scopeLabel('host')).toBe('The Home Assistant OS device')
    expect(scopeLabel('container')).toBe("This app's own container only")
    expect(scopeLabel('somewhere-new')).toBe('somewhere-new')
  })
})

describe('labels', () => {
  it('names the Wazuh daemons in plain language and leaves unknown ones alone', () => {
    expect(daemonLabel('wazuh-syscheckd')).toBe('File integrity and rootkit checks')
    expect(daemonLabel('wazuh-future-d')).toBe('wazuh-future-d')
  })

  it('names the modules and leaves unknown ones alone', () => {
    expect(moduleLabel('fim')).toBe('File integrity')
    expect(moduleLabel('brand_new')).toBe('brand_new')
  })

  it('treats active response and remote commands as the ones to be careful with', () => {
    expect([...riskyWhenOn].sort()).toEqual(['active_response', 'remote_commands'])
  })
})
