import { mount, type ComponentMountingOptions } from '@vue/test-utils'
import { defineComponent, h, type Component } from 'vue'
import { VApp } from 'vuetify/components'
import { createAppVuetify } from '@/plugins/vuetify'

/** Mounts a component with the app's Vuetify setup. */
export function mountWithVuetify(
  component: Component,
  options: ComponentMountingOptions<Component> = {},
) {
  return mount(component, {
    ...options,
    global: {
      ...options.global,
      plugins: [createAppVuetify(), ...(options.global?.plugins ?? [])],
    },
  })
}

/** Mounts a component inside <v-app>, which layout components such as <v-app-bar> need. */
export function mountInApp(component: Component, props: Record<string, unknown> = {}) {
  const Wrapper = defineComponent({
    setup: () => () => h(VApp, null, { default: () => h(component, props) }),
  })
  return mount(Wrapper, { global: { plugins: [createAppVuetify()] } })
}
