<script setup>
import { ref, provide } from 'vue'

import Account from './components/Account.vue'
import Login from './components/Login.vue'

const token = ref(localStorage.getItem('token'))
provide('token', token)

function login(tok) {
  token.value = tok
  if (tok) {
    localStorage.setItem('token', tok)
  } else {
    localStorage.removeItem('token')
  }
}
</script>

<template>
  <h1>The Family Bank!</h1>

  <Login v-if="token === null" @login="(tok) => login(tok)" />
  <Account v-else />
  <p><button v-if="token !== null" @click="login(null)">Log Me Out!</button></p>
</template>

<style scoped>

</style>
