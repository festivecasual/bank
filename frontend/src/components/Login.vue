<script setup>
import { ref } from 'vue'

const emit = defineEmits(['login'])

const username = ref(null)
const password = ref(null)

function handleLogin() {
    fetch('/api/session', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'username': username.value.value,
            'password': password.value.value
        })
    }).then((response) => {
        if (response.ok) {
            return response.json()
        } else {
            throw new Error('Login Unsuccessful')
        }
    }).then((json) => {
        emit('login', json.token)
    }).catch((e) => {
        alert('wups')
    })
}
</script>

<template>
    <h2>Login</h2>
    <input class="input" type="text" placeholder="username" ref="username">
    <input class="input" type="password" placeholder="password" ref="password">
    <button @click="handleLogin()">Log Me In!</button>
</template>

<style scoped>

</style>
