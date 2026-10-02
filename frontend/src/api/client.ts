import axios from 'axios'
import { useAuthStore } from '@/stores/auth'

declare module 'axios' {
  interface AxiosRequestConfig {
    /** Session counter when the request was issued; only that session may be ended by its 401. */
    sessionGeneration?: number
  }
}
const WRITE_METHODS = new Set(['post', 'put', 'patch', 'delete'])
// Same-origin requests carry the HttpOnly session cookie automatically; no token is attached here.
const client = axios.create({ baseURL: '/api/v1', timeout: 20_000, headers: { 'Content-Type': 'application/json' } })
client.interceptors.request.use(async config => {
  const { csrfToken, mode, session } = useAuthStore.getState()
  config.sessionGeneration ??= session
  if (mode === 'demo') {
    const { demoAdapter } = await import('./demo')
    config.adapter = demoAdapter
  } else if (csrfToken && WRITE_METHODS.has((config.method || 'get').toLowerCase()) && !config.headers.has('X-CSRF-Token')) {
    config.headers.set('X-CSRF-Token', csrfToken)
  }
  return config
})
client.interceptors.response.use(response => response, error => {
  const state = useAuthStore.getState()
  if (error.response?.status === 401 && error.config?.url !== '/auth/login' && state.mode === 'live' && state.isAuthenticated && error.config?.sessionGeneration === state.session) state.logout()
  return Promise.reject(error)
})
export default client
