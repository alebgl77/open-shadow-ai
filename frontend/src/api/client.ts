import axios from 'axios'
import { useAuthStore } from '@/stores/auth'
const client = axios.create({ baseURL: '/api/v1', timeout: 20_000, headers: { 'Content-Type': 'application/json' } })
client.interceptors.request.use(async config => {
  const { token, mode } = useAuthStore.getState()
  if (mode === 'demo') {
    const { demoAdapter } = await import('./demo')
    config.adapter = demoAdapter
  } else if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})
client.interceptors.response.use(response => response, error => {
  const state = useAuthStore.getState()
  if (error.response?.status === 401 && error.config?.url !== '/auth/login' && state.mode === 'live' && state.token && error.config?.headers?.Authorization === `Bearer ${state.token}`) state.logout()
  return Promise.reject(error)
})
export default client
