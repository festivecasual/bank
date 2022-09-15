<script setup>
import { ref, provide } from 'vue'

import Account from './components/Account.vue'
import Login from './components/Login.vue'

const auth = ref({
  'token': localStorage.getItem('token'),
  'username': localStorage.getItem('username'),
  'usertype': localStorage.getItem('usertype')
})
provide('auth', auth)

const activeUser = ref(null)
const userList = ref([])

function login(token, username, usertype) {
  auth.value = {
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

  if (usertype == 'standard') {
    activeUser.value = username
  } else if (usertype == 'admin') {
    fetch('/bank/api/user', {
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
        userList.value = json
    }).catch((e) => {
        logout()
    })
  } else {
    activeUser.value = null
  }
}

const logout = () => login(null, null, null)
</script>

<template>
  <section class="section">
    <div class="container">
      <div class="columns">
        <div class="column is-8">
          <p class="title">The Family Bank</p>
        </div>
        <div class="column is-2">
          <div v-if="auth.usertype == 'admin'">
            <div class="dropdown is-hoverable">
              <div class="dropdown-trigger">
                <button class="button" aria-haspopup="true" aria-controls="dropdown-menu">
                  <span>{{ activeUser ? activeUser : 'Choose a user...' }}</span>
                  <span class="icon is-small">
                    <i class="fas fa-angle-down" aria-hidden="true"></i>
                  </span>
                </button>
              </div>
              <div class="dropdown-menu" id="dropdown-menu" role="menu">
                <div class="dropdown-content">
                  <a 
                    v-for="user in userList"
                    href="#"
                    class="dropdown-item"
                    :class="{'is-active': user == activeUser}"
                    @click.prevent="activeUser = user"
                  >
                    {{ user }}
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="column is-2">
          <button v-if="auth.token !== null" class="button is-link mr-6" @click="logout()">Log Out&nbsp;<strong>{{ auth.username }}</strong></button>
        </div>
      </div>

      <Login v-if="!auth.token" @login="(token, username, usertype) => login(token, username, usertype)" />

      <Account v-if="activeUser" :user="activeUser" @apiFailure="logout()" />

    </div>
  </section>
</template>

<style scoped>

</style>
