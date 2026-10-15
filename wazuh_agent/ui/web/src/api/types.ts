// The JSON documents the status service returns. They mirror ui/server (status.go, updates.go,
// connection.go); keep the two in step.

export type StateName =
  'starting' | 'stale' | 'stopped' | 'degraded' | 'disconnected' | 'connecting' | 'running'

export interface Daemon {
  name: string
  running: boolean
  expected: boolean
}

export interface Connection {
  status: string
  last_keepalive?: string
  last_ack?: string
  messages_sent?: string
  buffered?: string
}

export interface Registration {
  registered: boolean
  id?: string
  name?: string
}

export interface Summary {
  agent: { name: string; groups: string[]; config_profile: string; version: string }
  manager: {
    addresses: string[]
    port: number
    protocol: string
    enrollment: {
      enabled: boolean
      address: string
      port: number
      password_set: boolean
      verified: boolean
    }
  }
  modules: Record<string, boolean>
  host: Record<string, string | null>
  app: { version: string | null }
}

export interface Status {
  state: StateName
  headline: string
  detail: string
  updated_at?: string
  daemons: Daemon[]
  connection: Connection
  registration: Registration
  summary?: Summary
}

export interface AgentUpdate {
  installed: string
  latest?: string
  available: boolean
  error?: string
}

export interface AppUpdate {
  version?: string
  latest?: string
  available: boolean
  error?: string
}

export interface UpdateInfo {
  enabled: boolean
  checked_at?: string
  agent: AgentUpdate
  app: AppUpdate
}

export interface ConnectionResult {
  host: string
  port: number
  purpose: 'events' | 'enrollment'
  tested: boolean
  reachable: boolean
  millis?: number
  note?: string
}
