<script setup lang="ts">
import { computed } from 'vue'
import { mdiLanConnect } from '@mdi/js'
import type { ConnectionResult, Status } from '@/api/types'
import { timeAgo } from '@/utils/time'

const props = defineProps<{
  status: Status | null
  results: ConnectionResult[] | null
  testing: boolean
  testError: Error | null
  now: Date
}>()

defineEmits<{ test: [] }>()

const connection = computed(() => props.status?.connection)
const manager = computed(() => props.status?.summary?.manager)

const tone = computed(() => {
  switch (connection.value?.status) {
    case 'connected':
      return 'success'
    case 'disconnected':
      return 'error'
    default:
      return 'info'
  }
})
const statusText = computed(() => connection.value?.status || 'waiting')
</script>

<template>
  <v-card class="panel pa-5" data-test="connection">
    <div class="panel-title mb-4">
      <v-icon :icon="mdiLanConnect" size="20" aria-hidden="true" />Connection
    </div>

    <v-chip :color="tone" class="mb-4 mono" data-test="status">{{ statusText }}</v-chip>

    <dl class="facts">
      <dt>Manager</dt>
      <dd class="mono">
        <template v-if="manager?.addresses.length">
          <div v-for="address in manager.addresses" :key="address">
            {{ address }}:{{ manager.port }} {{ manager.protocol.toUpperCase() }}
          </div>
        </template>
        <span v-else>—</span>
      </dd>
      <dt>Last keep-alive</dt>
      <dd data-test="keepalive">{{ timeAgo(connection?.last_keepalive, now) }}</dd>
      <dt>Last reply</dt>
      <dd data-test="ack">{{ timeAgo(connection?.last_ack, now) }}</dd>
      <dt>Messages sent</dt>
      <dd class="mono">{{ connection?.messages_sent ?? '—' }}</dd>
      <dt>Waiting to send</dt>
      <dd class="mono">{{ connection?.buffered ?? '—' }}</dd>
    </dl>

    <v-btn
      class="mt-4"
      :loading="testing"
      :disabled="!manager"
      data-test="test"
      @click="$emit('test')"
    >
      Test the connection
    </v-btn>

    <v-alert
      v-if="testError"
      type="error"
      variant="tonal"
      density="compact"
      class="mt-3"
      data-test="test-error"
    >
      The test could not run: {{ testError.message }}
    </v-alert>

    <ul v-if="results" class="mt-3 pl-0" style="list-style: none" data-test="results">
      <li
        v-for="result in results"
        :key="`${result.host}:${result.port}:${result.purpose}`"
        class="mb-1"
      >
        <v-chip
          :color="!result.tested ? 'secondary' : result.reachable ? 'success' : 'error'"
          class="mr-2"
          data-test="result"
        >
          {{ !result.tested ? 'not tested' : result.reachable ? 'reachable' : 'unreachable' }}
        </v-chip>
        <span class="mono">{{ result.host }}:{{ result.port }}</span>
        <span class="text-medium-emphasis"> · {{ result.purpose }}</span>
        <span v-if="result.tested && result.reachable" class="text-medium-emphasis">
          · {{ result.millis }} ms</span
        >
        <div v-if="result.note" class="text-caption text-medium-emphasis ml-1">
          {{ result.note }}
        </div>
      </li>
      <li v-if="!results.length" class="text-medium-emphasis">
        Nothing to test: no manager is configured.
      </li>
    </ul>
  </v-card>
</template>
