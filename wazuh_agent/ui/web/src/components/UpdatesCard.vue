<script setup lang="ts">
import { computed } from 'vue'
import { mdiUpdate } from '@mdi/js'
import type { UpdateInfo } from '@/api/types'
import { timeAgo } from '@/utils/time'

const props = defineProps<{
  info: UpdateInfo | null
  busy: boolean
  error: Error | null
  now: Date
}>()

defineEmits<{ refresh: [] }>()

const agent = computed(() => props.info?.agent)
const app = computed(() => props.info?.app)

const agentChip = computed(() => {
  if (agent.value?.error) return { color: 'warning', text: 'check failed' }
  if (agent.value?.available) return { color: 'info', text: 'update available' }
  return { color: 'success', text: 'up to date' }
})
</script>

<template>
  <v-card class="panel pa-5" data-test="updates">
    <div class="panel-title mb-4">
      <v-icon :icon="mdiUpdate" size="20" aria-hidden="true" />Updates
    </div>

    <v-alert
      v-if="error"
      type="warning"
      variant="tonal"
      density="compact"
      class="mb-3"
      data-test="error"
    >
      Could not check for updates: {{ error.message }}
    </v-alert>

    <p v-if="info && !info.enabled" class="mb-0" data-test="disabled">
      Update checks are turned off in the app's configuration (<span class="mono"
        >ui_update_check</span
      >).
    </p>
    <p v-else-if="!info" class="text-medium-emphasis mb-0" data-test="loading">Checking…</p>

    <template v-else-if="agent">
      <dl class="facts mb-3">
        <dt>Wazuh agent</dt>
        <dd>
          <span class="mono" data-test="agent-installed">{{ agent.installed || '—' }}</span>
          <template v-if="agent.latest && agent.latest !== agent.installed">
            → <span class="mono" data-test="agent-latest">{{ agent.latest }}</span>
          </template>
          <v-chip :color="agentChip.color" class="ml-2" data-test="agent-chip">{{
            agentChip.text
          }}</v-chip>
        </dd>
        <template v-if="app?.version || app?.error">
          <dt>This app</dt>
          <dd>
            <span class="mono" data-test="app-version">{{ app.version ?? '—' }}</span>
            <template v-if="app.available">
              → <span class="mono" data-test="app-latest">{{ app.latest }}</span>
            </template>
            <v-chip v-if="app.error" color="warning" class="ml-2" data-test="app-error"
              >check failed</v-chip
            >
            <v-chip
              v-else
              :color="app.available ? 'info' : 'success'"
              class="ml-2"
              data-test="app-chip"
            >
              {{ app.available ? 'update available' : 'up to date' }}
            </v-chip>
          </dd>
        </template>
      </dl>

      <p v-if="app?.available" class="text-body-2 mb-3" data-test="app-hint">
        An update of this app is ready. Install it in
        <strong>Settings → Apps → Wazuh Agent</strong>. Update your Wazuh manager first if the new
        agent is a newer minor version than the manager.
      </p>
      <p v-else-if="agent.available" class="text-body-2 mb-3" data-test="agent-hint">
        Wazuh has published a newer agent. It reaches this device as an update of the app, which
        appears in
        <strong>Settings → Apps</strong> once it has been released and tested.
      </p>
      <p v-if="agent.error" class="text-body-2 text-medium-emphasis mb-3" data-test="agent-error">
        {{ agent.error }}
      </p>
      <p v-if="app?.error" class="text-body-2 text-medium-emphasis mb-3" data-test="app-error-text">
        {{ app.error }}
      </p>
    </template>

    <div class="d-flex align-center ga-3 mt-1">
      <v-btn
        :loading="busy"
        :disabled="info?.enabled === false"
        data-test="refresh"
        @click="$emit('refresh')"
      >
        Check now
      </v-btn>
      <span v-if="info?.checked_at" class="text-caption text-medium-emphasis" data-test="checked">
        Checked {{ timeAgo(info.checked_at, now) }}
      </span>
    </div>
  </v-card>
</template>
