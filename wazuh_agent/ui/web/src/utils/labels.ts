import {
  mdiAlertCircleOutline,
  mdiCheckCircleOutline,
  mdiHelpCircleOutline,
  mdiLanDisconnect,
  mdiProgressClock,
  mdiStopCircleOutline,
} from '@mdi/js'
import type { StateName } from '@/api/types'

export type Tone = 'success' | 'warning' | 'error' | 'info' | 'neutral'

export interface StateLook {
  tone: Tone
  icon: string
  pulse: boolean
}

/** How each agent state is shown: a colour, an icon and whether the ring pulses. */
export const stateLook: Record<StateName, StateLook> = {
  running: { tone: 'success', icon: mdiCheckCircleOutline, pulse: true },
  degraded: { tone: 'warning', icon: mdiAlertCircleOutline, pulse: false },
  connecting: { tone: 'info', icon: mdiProgressClock, pulse: true },
  starting: { tone: 'info', icon: mdiProgressClock, pulse: true },
  disconnected: { tone: 'error', icon: mdiLanDisconnect, pulse: false },
  stopped: { tone: 'error', icon: mdiStopCircleOutline, pulse: false },
  stale: { tone: 'warning', icon: mdiHelpCircleOutline, pulse: false },
}

const daemonNames: Record<string, string> = {
  'wazuh-agentd': 'Connection to the manager',
  'wazuh-execd': 'Active response',
  'wazuh-logcollector': 'Log collection',
  'wazuh-modulesd': 'Inventory, assessment and modules',
  'wazuh-syscheckd': 'File integrity and rootkit checks',
}

/** A plain-language name for a Wazuh daemon; unknown daemons keep their own name. */
export function daemonLabel(name: string): string {
  return daemonNames[name] ?? name
}

export const moduleLabels: Record<string, string> = {
  journal: 'Host journal',
  fim: 'File integrity',
  inventory: 'System inventory',
  rootcheck: 'Rootkit checks',
  sca: 'Configuration assessment',
  active_response: 'Active response',
  remote_commands: 'Remote commands',
}

/** Modules where "on" is the cautious state; the others are cautious when off. */
export const riskyWhenOn = new Set(['active_response', 'remote_commands'])

export function moduleLabel(key: string): string {
  return moduleLabels[key] ?? key
}
