<script setup>
import { ref, provide } from 'vue'

import Account from './components/Account.vue'
import Login from './components/Login.vue'

const user = ref({
  'token': localStorage.getItem('token'),
  'username': localStorage.getItem('username'),
  'usertype': localStorage.getItem('usertype')
})
provide('user', user)

function login(token, username, usertype) {
  user.value = {
    'token': token,
    'username': username,
    'usertype': usertype
  }
  if (token) {
    localStorage.setItem('token', token)
    localStorage.setItem('username', username)
    localStorage.setItem('usertype', usertype)
  } else {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    localStorage.removeItem('usertype')
  }
}

const logout = () => login(null, null, null)
</script>

<template>
  <section class="section">
    <div class="container">
      <div class="columns">
        <div class="column is-10">
          <p class="title">The Family Bank</p>
        </div>
        <div class="column is-2">
          <div v-if="user.token !== null">
            <p><button class="button is-link mr-6" @click="logout()">Log Out&nbsp;<strong>{{ user.username }}</strong></button></p>
          </div>
        </div>
      </div>

      <Login v-if="!user.token" @login="(token, username, usertype) => login(token, username, usertype)" />

      <Account v-if="user.usertype == 'standard'" @apiFailure="logout()" />

    </div>
  </section>
</template>

<style scoped>

</style>
