<script setup>
import { ref, onMounted } from 'vue'

const emit = defineEmits(['login'])

const username = ref(null)
const password = ref(null)

const error = ref('')

onMounted(() => {
    username.value.focus()
})

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
        emit('login', json.token, json.username, json.usertype)
    }).catch((e) => {
        error.value = 'Please try again.'
    })
}
</script>

<template>
    <div class="columns">
        <div class="column is-4">
            <div class="notification is-light">{{ error || 'Welcome!  Please sign in.' }}</div>
            <form @submit.prevent="handleLogin()">
                <p class="m-3"><input class="input is-primary is-rounded" type="text" placeholder="username" ref="username"></p>
                <p class="m-3"><input class="input is-primary is-rounded" type="password" placeholder="password" ref="password"></p>
                <p class="m-3"><input type="submit" class="button is-primary is-rounded" value="Sign In"></p>
            </form>
        </div>
    </div>
</template>

<style scoped>

</style>
