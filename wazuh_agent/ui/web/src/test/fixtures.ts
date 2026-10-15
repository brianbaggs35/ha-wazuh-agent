import type { Status, Summary, UpdateInfo } from '@/api/types'

export const summary: Summary = {
  agent: {
    name: 'homeassistant',
    groups: ['default', 'iot'],
    config_profile: 'homeassistant',
    version: '4.14.9',
  },
  manager: {
    addresses: ['10.0.0.5'],
    port: 1514,
    protocol: 'tcp',
    enrollment: { enabled: true, address: '', port: 1515, password_set: true, verified: true },
  },
  modules: { journal: true, fim: true, inventory: true, rootcheck: false, active_response: false },
  host: {
    operating_system: 'Home Assistant OS 16.2',
    core_version: '2026.10.1',
    supervisor_version: '2026.10.0',
    machine: 'rpi4-64',
    arch: 'aarch64',
    channel: 'stable',
  },
  app: { version: '1.0.0' },
}

export function makeStatus(overrides: Partial<Status> = {}): Status {
  return {
    state: 'running',
    headline: 'Running and connected',
    detail: 'The agent is connected to the Wazuh manager and sending events.',
    updated_at: '2026-10-15T11:59:55Z',
    daemons: [
      { name: 'wazuh-agentd', running: true, expected: true },
      { name: 'wazuh-syscheckd', running: true, expected: true },
    ],
    connection: {
      status: 'connected',
      last_keepalive: '2026-10-15T11:59:50Z',
      last_ack: '2026-10-15T11:59:51Z',
      messages_sent: '36',
      buffered: '0',
    },
    registration: { registered: true, id: '001', name: 'homeassistant' },
    summary,
    ...overrides,
  }
}

export function makeUpdates(overrides: Partial<UpdateInfo> = {}): UpdateInfo {
  return {
    enabled: true,
    checked_at: '2026-10-15T11:55:00Z',
    agent: { installed: '4.14.9', latest: '4.14.9', available: false },
    app: { version: '1.0.0', latest: '1.0.0', available: false },
    ...overrides,
  }
}

export const now = new Date('2026-10-15T12:00:00Z')
