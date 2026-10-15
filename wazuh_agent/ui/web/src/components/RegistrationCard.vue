<script setup lang="ts">
import { computed } from 'vue'
import { mdiBadgeAccountOutline } from '@mdi/js'
import type { Status } from '@/api/types'

const props = defineProps<{ status: Status | null }>()

const registration = computed(() => props.status?.registration)
const agent = computed(() => props.status?.summary?.agent)
const enrollment = computed(() => props.status?.summary?.manager.enrollment)
const name = computed(() => registration.value?.name || agent.value?.name || '—')
</script>

<template>
  <v-card class="panel pa-5" data-test="registration">
    <div class="panel-title mb-4">
      <v-icon :icon="mdiBadgeAccountOutline" size="20" aria-hidden="true" />Registration
    </div>

    <v-chip v-if="registration?.registered" color="success" class="mb-4" data-test="registered">
      Registered with the manager
    </v-chip>
    <v-chip v-else color="info" class="mb-4" data-test="unregistered">
      {{
        enrollment?.enabled === false ? 'Not registered, enrollment is off' : 'Not registered yet'
      }}
    </v-chip>

    <dl class="facts">
      <dt>Name in Wazuh</dt>
      <dd class="mono">{{ name }}</dd>
      <dt>Agent ID</dt>
      <dd class="mono">{{ registration?.id ?? '—' }}</dd>
      <dt>Groups</dt>
      <dd>
        <template v-if="agent?.groups.length">
          <v-chip v-for="group in agent.groups" :key="group" class="mr-1 mono">{{ group }}</v-chip>
        </template>
        <span v-else>default</span>
      </dd>
      <dt>Config profile</dt>
      <dd class="mono">{{ agent?.config_profile || '—' }}</dd>
      <dt>Enrollment</dt>
      <dd>
        <template v-if="enrollment?.enabled">
          Automatic, on port <span class="mono">{{ enrollment.port }}</span>
          <v-chip v-if="enrollment.password_set" class="ml-2" color="success" data-test="password">
            password protected
          </v-chip>
          <v-chip v-if="enrollment.verified" class="ml-2" color="success" data-test="verified">
            manager verified
          </v-chip>
        </template>
        <span v-else>Off</span>
      </dd>
    </dl>

    <p v-if="registration?.registered" class="text-body-2 mt-4 mb-0" data-test="where">
      In the Wazuh dashboard open <strong>Agents</strong> and look for
      <span class="mono">{{ name }}</span
      >.
    </p>
  </v-card>
</template>
