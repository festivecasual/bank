<script setup>
import { inject } from 'vue'

const token = inject('token')
</script>

<template>
    <p>This is an account view!  My token is {{ token }}!</p>
</template>

<style scoped>

</style>
