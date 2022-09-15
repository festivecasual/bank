<script setup>
import { inject, ref, onMounted, computed, watch } from 'vue'
import { formatCurrency } from '/src/main.js'

const auth = inject('auth')

const transactions = ref([])
const balance = computed(() => transactions.value.length > 0 ? transactions.value[0][4] : 0)

const addDate = ref((new Date()).toISOString().split('T')[0])
const addMemo = ref('')
const addAmount = ref('0.00')

const props = defineProps(['user'])

const emit = defineEmits(['apiFailure'])

onMounted(() => {
    refreshUser(props.user)
})

watch(() => props.user, async (newUser, oldUser) => {
    refreshUser(newUser)
})

function refreshUser(newUser) {
    let apiTarget = '/bank/api/transaction'
    if (auth.value.username != newUser) {
        apiTarget = `/bank/api/user/${newUser}/transaction`
    }
    fetch(apiTarget, {
        'method': 'GET',
        'headers': {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + auth.value.token
        }
    }).then((response) => {
        if (response.ok) {
            return response.json()
        } else {
            throw new Error('API query failed')
        }
    }).then((json) => {
        transactions.value = json.data
    }).catch((e) => {
        emit('apiFailure')
    })
}

function handleAddTransaction() {
    let amt = Math.floor(addAmount.value * 100) / 100
    if (Number.isNaN(amt)) {
        addAmount.value = '0.00'
        return
    }
    fetch('/bank/api/transaction', {
        'method': 'POST',
        'headers': {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + auth.value.token
        },
        body: JSON.stringify({
            'txndate': addDate.value,
            'memo' : addMemo.value,
            'username': props.user,
            'amount': amt
        })
    }).then((response) => {
        if (response.ok) {
            addMemo.value = ''
            addAmount.value = '0.00'
            refreshUser(props.user)
        } else {
            throw new Error('API query failed')
        }
    }).catch((e) => {
        emit('apiFailure')
    })
}

function handleDelete(txn) {
    fetch(`/bank/api/transaction/${txn[3]}`, {
        'method': 'DELETE',
        'headers': {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + auth.value.token
        }
    }).then((response) => {
        if (response.ok) {
            refreshUser(props.user)
        } else {
            throw new Error('API query failed')
        }
    }).catch((e) => {
        emit('apiFailure')
    })
}
</script>

<template>
    <div class="is-flex is-flex-direction-row is-flex-wrap-wrap">
        <div class="is-flex is-flex-direction-column mr-6">
            <div class="notification is-success">
                <p><strong>Available Balance</strong></p>
                <p class="subtitle is-2">{{ formatCurrency(balance) }}</p>
            </div>
            <div class="is-flex-grow-1"></div>
        </div>
        <div class="container">
            <form v-if="auth.usertype == 'admin'" @submit.prevent="handleAddTransaction()">
                <div class="columns mt-3 mb-6">
                    <div class="column is-narrow"><input type="date" class="input" v-model="addDate"></div>
                    <div class="column"><input type="text" class="input" placeholder="Memo" v-model="addMemo"></div>
                    <div class="column is-2"><input type="text" class="input" placeholder="Amount" v-model="addAmount"></div>
                    <div class="column is-narrow"><button type="submit" class="button is-primary is-rounded">Add</button></div>
                </div>
            </form>
            <table class="table is-fullwidth is-striped is-hoverable">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Description</th>
                        <th>Amount</th>
                        <th>Balance</th>
                        <th v-if="auth.usertype == 'admin'"></th>
                    </tr>
                </thead>
                <tbody>
                    <tr v-for="transaction in transactions">
                        <td>{{ transaction[0] }}</td>
                        <td>{{ transaction[1] }}</td>
                        <td>{{ formatCurrency(transaction[2]) }}</td>
                        <td>{{ formatCurrency(transaction[4]) }}</td>
                        <td v-if="auth.usertype == 'admin'"><button class="button is-danger is-rounded" @click.prevent="handleDelete(transaction)">X</button></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</template>

<style scoped>

</style>
