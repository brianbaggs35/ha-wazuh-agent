<script setup lang="ts">
import { computed } from 'vue'
import { mdiCloudOffOutline, mdiProgressClock } from '@mdi/js'
import type { Status } from '@/api/types'
import { stateLook, type Tone } from '@/utils/labels'

const props = defineProps<{ status: Status | null; error: Error | null }>()

interface Banner {
  tone: Tone
  icon: string
  pulse: boolean
  headline: string
  detail: string
}

const banner = computed<Banner>(() => {
  if (props.status) {
    const look = stateLook[props.status.state]
    return { ...look, headline: props.status.headline, detail: props.status.detail }
  }
  if (props.error) {
    return {
      tone: 'error',
      icon: mdiCloudOffOutline,
      pulse: false,
      headline: 'Status unavailable',
      detail:
        'This page cannot reach the app. Check that the app is started; if it is, restart it from the app page.',
    }
  }
  return {
    tone: 'info',
    icon: mdiProgressClock,
    pulse: true,
    headline: 'Loading',
    detail: 'Asking the agent for its status…',
  }
})

const facts = computed(() => {
  const summary = props.status?.summary
  const manager = summary
    ? `${summary.manager.addresses[0] ?? 'not set'}:${summary.manager.port} (${summary.manager.protocol.toUpperCase()})`
    : '—'
  return [
    { label: 'Agent', value: summary?.agent.name || props.status?.registration.name || '—' },
    { label: 'Agent ID', value: props.status?.registration.id ?? 'not registered yet' },
    { label: 'Manager', value: manager },
    { label: 'Wazuh', value: summary?.agent.version || '—' },
  ]
})
</script>

<template>
  <v-card
    class="hero pa-5 pa-sm-6"
    :style="{ '--v-theme-hero': `var(--v-theme-${banner.tone})` }"
    data-test="hero"
  >
    <div class="d-flex flex-column flex-sm-row align-sm-center ga-5">
      <div :class="['hero-ring', { 'hero-ring--pulse': banner.pulse }]" aria-hidden="true">
        <v-icon :icon="banner.icon" size="44" />
      </div>
      <div class="flex-grow-1" style="min-width: 0">
        <div class="eyebrow mb-1">Agent status</div>
        <h1 class="text-h4 font-weight-bold mb-1" aria-live="polite" data-test="headline">
          {{ banner.headline }}
        </h1>
        <p class="text-body-1 mb-0" style="max-width: 46rem" data-test="detail">
          {{ banner.detail }}
        </p>
      </div>
    </div>
    <v-divider class="my-5" />
    <div class="hero-facts">
      <div v-for="fact in facts" :key="fact.label">
        <div class="hero-fact-label">{{ fact.label }}</div>
        <div class="mono text-body-1">{{ fact.value }}</div>
      </div>
    </div>
  </v-card>
</template>
