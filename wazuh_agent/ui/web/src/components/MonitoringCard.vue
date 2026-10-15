<script setup lang="ts">
import { computed } from 'vue'
import { mdiCheck, mdiClose, mdiRadar } from '@mdi/js'
import type { Status } from '@/api/types'
import { moduleLabel, riskyWhenOn } from '@/utils/labels'

const props = defineProps<{ status: Status | null }>()

const modules = computed(() =>
  Object.entries(props.status?.summary?.modules ?? {}).map(([key, on]) => ({
    key,
    label: moduleLabel(key),
    on,
    caution: on && riskyWhenOn.has(key),
  })),
)
</script>

<template>
  <v-card class="panel pa-5" data-test="monitoring">
    <div class="panel-title mb-4">
      <v-icon :icon="mdiRadar" size="20" aria-hidden="true" />What is monitored
    </div>

    <p v-if="!modules.length" class="text-medium-emphasis mb-0" data-test="none">
      The configuration summary is not available yet.
    </p>
    <ul v-else class="pl-0 mb-0" style="list-style: none">
      <li
        v-for="module in modules"
        :key="module.key"
        class="d-flex align-center py-1"
        data-test="module"
      >
        <v-icon
          :icon="module.on ? mdiCheck : mdiClose"
          :color="module.caution ? 'warning' : module.on ? 'success' : undefined"
          size="18"
          class="mr-3"
          aria-hidden="true"
        />
        <span :class="{ 'text-medium-emphasis': !module.on }">{{ module.label }}</span>
        <v-chip v-if="module.caution" color="warning" class="ml-auto" data-test="caution"
          >on, use with care</v-chip
        >
        <span v-else class="ml-auto text-caption text-medium-emphasis">{{
          module.on ? 'on' : 'off'
        }}</span>
      </li>
    </ul>
  </v-card>
</template>
