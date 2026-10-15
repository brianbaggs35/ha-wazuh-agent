<script setup lang="ts">
import { computed } from 'vue'
import { mdiBrightness4, mdiThemeLightDark, mdiWhiteBalanceSunny } from '@mdi/js'
import type { ThemePreference } from '@/composables/useThemePreference'
import { timeAgo } from '@/utils/time'
import BrandMark from './BrandMark.vue'

const props = defineProps<{
  fetchedAt: Date | null
  offline: boolean
  now: Date
  theme: ThemePreference
}>()

defineEmits<{ 'cycle-theme': [] }>()

const themeIcon = computed(() =>
  props.theme === 'light'
    ? mdiWhiteBalanceSunny
    : props.theme === 'dark'
      ? mdiBrightness4
      : mdiThemeLightDark,
)

// "Updated" is dropped on narrow screens, where the chip would otherwise be cut off.
const live = computed(() =>
  props.offline
    ? { prefix: '', text: 'Offline' }
    : props.fetchedAt
      ? { prefix: 'Updated ', text: timeAgo(props.fetchedAt.toISOString(), props.now) }
      : { prefix: '', text: 'Connecting…' },
)
</script>

<template>
  <v-app-bar flat border="b" density="comfortable">
    <div class="d-flex align-center ga-3 px-4">
      <BrandMark :size="30" />
      <div>
        <div class="text-subtitle-1 font-weight-bold" style="line-height: 1.1">Wazuh Agent</div>
        <div class="eyebrow d-none d-sm-block">Home Assistant app</div>
      </div>
    </div>
    <v-spacer />
    <v-chip
      class="mr-2 mono"
      :color="offline ? 'error' : 'success'"
      data-test="live"
      aria-live="polite"
    >
      <span class="mr-2" aria-hidden="true">●</span>
      <!-- One wrapper: the chip lays its children out as flex items, which would trim the space after "Updated". -->
      <span
        ><span v-if="live.prefix" class="d-none d-sm-inline">{{ live.prefix }}</span
        >{{ live.text }}</span
      >
    </v-chip>
    <v-btn
      :icon="themeIcon"
      variant="text"
      class="mr-2"
      :aria-label="`Theme: ${theme}. Click to change.`"
      data-test="theme"
      @click="$emit('cycle-theme')"
    />
  </v-app-bar>
</template>
