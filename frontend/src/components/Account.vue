<script setup>
import { inject, ref, onMounted } from 'vue'
import { formatCurrency } from '/src/main.js'

const user = inject('user')

const balance = ref(0)
const transactions = ref([])

const emit = defineEmits(['apiFailure'])

onMounted(() => {
    fetch('/api/balance', {
        'method': 'GET',
        'headers': {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + user.value.token
        }
    }).then((response) => {
        if (response.ok) {
            return response.json()
        } else {
            throw new Error('API Query Failed')
        }
    }).then((json) => {
        balance.value = json.balance
    }).catch((e) => {
        emit('apiFailure')
    })

    fetch('/api/transaction', {
        'method': 'GET',
        'headers': {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + user.value.token
        }
    }).then((response) => {
        if (response.ok) {
            return response.json()
        } else {
            throw new Error('API Query Failed')
        }
    }).then((json) => {
        let running = 0
        let txns = json.data.map((r) => {
            let r_ = r.concat([balance.value - running])
            running += r[2]
            return r_
        })
        transactions.value = txns
    }).catch((e) => {
        emit('apiFailure')
    })
})
</script>

<template>
    <div class="columns">
        <div class="column is-2">
            <div class="notification is-success">
                <p><strong>Available Balance</strong></p>
                <p class="subtitle is-2">{{ formatCurrency(balance) }}</p>
            </div>
        </div>
        <div class="column is-1"></div>
        <div class="column">
            <table class="table is-fullwidth">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Description</th>
                        <th>Amount</th>
                        <th>Balance</th>
                    </tr>
                </thead>
                <tbody>
                    <tr v-for="transaction in transactions">
                        <td>{{ transaction[0] }}</td>
                        <td>{{ transaction[1] }}</td>
                        <td>{{ formatCurrency(transaction[2]) }}</td>
                        <td>{{ formatCurrency(transaction[3]) }}</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</template>

<style scoped>

</style>
