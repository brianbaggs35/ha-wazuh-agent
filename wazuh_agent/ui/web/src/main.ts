import { createApp } from 'vue'
import App from './App.vue'
import { createAppVuetify } from './plugins/vuetify'
import './styles/main.css'

createApp(App).use(createAppVuetify()).mount('#app')
