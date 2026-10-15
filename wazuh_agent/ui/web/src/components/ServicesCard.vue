<script setup lang="ts">
import { mdiCogs } from '@mdi/js'
import type { Status } from '@/api/types'
import { daemonLabel } from '@/utils/labels'

defineProps<{ status: Status | null }>()
</script>

<template>
  <v-card class="panel pa-5" data-test="services">
    <div class="panel-title mb-4">
      <v-icon :icon="mdiCogs" size="20" aria-hidden="true" />Agent services
    </div>

    <p v-if="!status?.daemons.length" class="text-medium-emphasis mb-0" data-test="none">
      No service has reported yet.
    </p>
    <ul v-else class="pl-0 mb-0" style="list-style: none">
      <li
        v-for="daemon in status.daemons"
        :key="daemon.name"
        class="d-flex align-center justify-space-between py-1"
        data-test="daemon"
      >
        <div>
          <div>{{ daemonLabel(daemon.name) }}</div>
          <div class="text-caption text-medium-emphasis mono">{{ daemon.name }}</div>
        </div>
        <v-chip :color="daemon.running ? 'success' : daemon.expected ? 'error' : 'secondary'">
          {{ daemon.running ? 'running' : daemon.expected ? 'stopped' : 'off' }}
        </v-chip>
      </li>
    </ul>
  </v-card>
</template>
