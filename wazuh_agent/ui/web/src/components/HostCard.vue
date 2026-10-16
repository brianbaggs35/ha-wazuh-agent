<script setup lang="ts">
import { computed } from 'vue'
import { mdiHomeAutomation } from '@mdi/js'
import type { Status } from '@/api/types'
import { scopeLabel } from '@/utils/labels'

const props = defineProps<{ status: Status | null }>()

const rows = computed(() => {
  const host = props.status?.summary?.host ?? {}
  const wanted: [string, string][] = [
    ['Monitoring', 'scope'],
    ['Host name', 'hostname'],
    ['Home Assistant OS', 'operating_system'],
    ['Core', 'core_version'],
    ['Supervisor', 'supervisor_version'],
    ['Machine', 'machine'],
    ['Architecture', 'arch'],
    ['Update channel', 'channel'],
  ]
  return wanted
    .filter(([, key]) => host[key])
    .map(([label, key]) => ({ label, value: key === 'scope' ? scopeLabel(host[key]!) : host[key] }))
})
</script>

<template>
  <v-card class="panel pa-5" data-test="host">
    <div class="panel-title mb-4">
      <v-icon :icon="mdiHomeAutomation" size="20" aria-hidden="true" />This device
    </div>
    <p v-if="!rows.length" class="text-medium-emphasis mb-0" data-test="none">
      Home Assistant did not report details about this device.
    </p>
    <dl v-else class="facts">
      <template v-for="row in rows" :key="row.label">
        <dt>{{ row.label }}</dt>
        <dd class="mono" data-test="row">{{ row.value }}</dd>
      </template>
    </dl>
    <p class="text-caption text-medium-emphasis mt-4 mb-0">
      These are sent to Wazuh as labels on every event, so you can filter on them in the dashboard.
    </p>
  </v-card>
</template>
