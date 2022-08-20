import 'bulma/css/bulma.css'

import { createApp } from 'vue'
import App from './App.vue'

createApp(App).mount('#app')

export function formatCurrency(amount) {
    return (amount < 0 ? '-' : '') + '$' + Math.abs(amount).toFixed(2)
}
