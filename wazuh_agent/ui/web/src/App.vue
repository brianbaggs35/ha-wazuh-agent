<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useTheme } from 'vuetify'
import { api } from '@/api/client'
import { useAction } from '@/composables/useAction'
import { usePoller } from '@/composables/usePoller'
import { useThemePreference } from '@/composables/useThemePreference'
import AppHeader from '@/components/AppHeader.vue'
import ConnectionCard from '@/components/ConnectionCard.vue'
import HostCard from '@/components/HostCard.vue'
import LogPanel from '@/components/LogPanel.vue'
import MonitoringCard from '@/components/MonitoringCard.vue'
import RegistrationCard from '@/components/RegistrationCard.vue'
import ServicesCard from '@/components/ServicesCard.vue'
import StatusHero from '@/components/StatusHero.vue'
import UpdatesCard from '@/components/UpdatesCard.vue'

const now = ref(new Date())
let clock: ReturnType<typeof setInterval> | undefined

const {
  data: status,
  error: statusError,
  fetchedAt,
  start: startStatus,
} = usePoller(api.status, 5000)
const { data: logLines, error: logError, start: startLogs } = usePoller(api.logs, 10000)
const {
  result: updates,
  error: updatesError,
  busy: updating,
  run: checkUpdates,
} = useAction(api.updates)
const {
  result: results,
  error: testError,
  busy: testing,
  run: testConnection,
} = useAction(api.connectionTest)

const theme = useTheme()
const { preference, cycle } = useThemePreference()
watch(preference, (value) => theme.change(value), { immediate: true })

onMounted(() => {
  clock = setInterval(() => {
    now.value = new Date()
  }, 1000)
  startStatus()
  startLogs()
  void checkUpdates(false)
})
onBeforeUnmount(() => clearInterval(clock))
</script>

<template>
  <v-app>
    <AppHeader
      :fetched-at="fetchedAt"
      :offline="statusError !== null"
      :now="now"
      :theme="preference"
      @cycle-theme="cycle"
    />
    <v-main>
      <v-container class="py-6" style="max-width: 1180px">
        <v-row>
          <v-col cols="12"><StatusHero :status="status" :error="statusError" /></v-col>
          <v-col cols="12" md="6"><RegistrationCard :status="status" /></v-col>
          <v-col cols="12" md="6">
            <ConnectionCard
              :status="status"
              :results="results"
              :testing="testing"
              :test-error="testError"
              :now="now"
              @test="testConnection()"
            />
          </v-col>
          <v-col cols="12" md="6"><ServicesCard :status="status" /></v-col>
          <v-col cols="12" md="6"><MonitoringCard :status="status" /></v-col>
          <v-col cols="12" md="6">
            <UpdatesCard
              :info="updates"
              :busy="updating"
              :error="updatesError"
              :now="now"
              @refresh="checkUpdates(true)"
            />
          </v-col>
          <v-col cols="12" md="6"><HostCard :status="status" /></v-col>
          <v-col cols="12"><LogPanel :lines="logLines ?? []" :error="logError" /></v-col>
        </v-row>
        <p class="text-caption text-medium-emphasis text-center mt-2 mb-0">
          A read-only view. Change settings in this app's Configuration tab.
        </p>
      </v-container>
    </v-main>
  </v-app>
</template>
