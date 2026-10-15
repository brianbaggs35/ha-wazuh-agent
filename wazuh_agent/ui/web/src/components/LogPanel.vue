<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { mdiContentCopy, mdiTextBoxOutline } from '@mdi/js'

const props = defineProps<{ lines: string[]; error: Error | null }>()

type Filter = 'all' | 'issues'
const filter = ref<Filter>('all')
const follow = ref(true)
const copied = ref(false)
const terminal = ref<HTMLElement | null>(null)

type Level = 'error' | 'warning' | 'info'

function levelOf(line: string): Level {
  if (/\b(ERROR|CRITICAL)\b/.test(line)) return 'error'
  if (/\bWARNING\b/.test(line)) return 'warning'
  return 'info'
}

const shown = computed(() =>
  props.lines
    .map((text, index) => ({ text, index, level: levelOf(text) }))
    .filter((line) => filter.value === 'all' || line.level !== 'info'),
)

watch(
  () => [props.lines, filter.value],
  async () => {
    if (!follow.value) return
    await nextTick()
    if (terminal.value) terminal.value.scrollTop = terminal.value.scrollHeight
  },
)

async function copy(): Promise<void> {
  try {
    await navigator.clipboard.writeText(shown.value.map((line) => line.text).join('\n'))
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    copied.value = false // the clipboard can be unavailable in an embedded frame
  }
}
</script>

<template>
  <v-card class="panel pa-5" data-test="log">
    <div class="d-flex flex-wrap align-center ga-3 mb-4">
      <div class="panel-title">
        <v-icon :icon="mdiTextBoxOutline" size="20" aria-hidden="true" />Agent log
      </div>
      <v-spacer />
      <v-btn-toggle
        v-model="filter"
        mandatory
        density="comfortable"
        variant="outlined"
        divided
        data-test="filter"
      >
        <v-btn value="all" data-test="filter-all">All</v-btn>
        <v-btn value="issues" data-test="filter-issues">Warnings and errors</v-btn>
      </v-btn-toggle>
      <v-switch
        v-model="follow"
        label="Follow"
        color="primary"
        density="compact"
        hide-details
        data-test="follow"
      />
      <v-btn :prepend-icon="mdiContentCopy" data-test="copy" @click="copy">{{
        copied ? 'Copied' : 'Copy'
      }}</v-btn>
    </div>

    <v-alert
      v-if="error"
      type="warning"
      variant="tonal"
      density="compact"
      class="mb-3"
      data-test="error"
    >
      The log could not be refreshed: {{ error.message }}
    </v-alert>

    <div
      ref="terminal"
      class="terminal mono"
      role="log"
      tabindex="0"
      aria-label="Agent log"
      data-test="terminal"
    >
      <template v-if="shown.length">
        <div v-for="line in shown" :key="line.index" :class="`log-${line.level}`" data-test="line">
          {{ line.text }}
        </div>
      </template>
      <div v-else class="log-muted" data-test="empty">
        {{ lines.length ? 'No warnings or errors in the last lines.' : 'The log is empty.' }}
      </div>
    </div>
  </v-card>
</template>
