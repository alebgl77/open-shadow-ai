import client from './client'
import { useAuthStore, type User } from '@/stores/auth'

export interface LoginResponse {
  access_token: string
  token_type: string
  user: User
}
export const SSO_LOGIN_PATH = '/api/v1/auth/sso/login'
export const SSO_FAILURE_MESSAGE = 'Single sign-on could not be completed. Start sign-in again, or use your local account. If this continues, contact your workspace administrator.'
export interface AuthProviders {
  local_enabled: boolean
  sso: null | { enabled: false } | { enabled: true; label: string; login_url: typeof SSO_LOGIN_PATH }
}

export function parseAuthProviders(value: unknown): AuthProviders {
  if (!value || typeof value !== 'object') throw new Error('Invalid sign-in configuration')
  const data = value as Record<string, unknown>
  if (typeof data.local_enabled !== 'boolean') throw new Error('Invalid local sign-in configuration')
  if (data.sso === null) return { local_enabled: data.local_enabled, sso: null }
  if (!data.sso || typeof data.sso !== 'object') throw new Error('Invalid SSO configuration')
  const sso = data.sso as Record<string, unknown>
  if (sso.enabled === false) return { local_enabled: data.local_enabled, sso: { enabled: false } }
  // Navigation accepts exactly the server's documented same-origin entry point.
  if (sso.enabled !== true || sso.login_url !== SSO_LOGIN_PATH || typeof sso.label !== 'string' || !sso.label.trim()) {
    throw new Error('Invalid SSO entry point')
  }
  return { local_enabled: data.local_enabled, sso: { enabled: true, label: sso.label.trim(), login_url: SSO_LOGIN_PATH } }
}
export async function getAuthProviders(): Promise<AuthProviders> {
  const { data } = await client.get<unknown>('/auth/providers')
  return parseAuthProviders(data)
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const { data } = await client.post<LoginResponse>('/auth/login', { username, password })
  return data
}

// Share only the pending exchange across Strict Mode's setup/cleanup/setup cycle.
// A settled response is released; no ticket or token is kept in module storage.
let pendingSsoExchange: Promise<LoginResponse> | null = null
let pendingSsoSession: number | null = null
export function exchangeSsoSession(): Promise<LoginResponse> {
  const state = useAuthStore.getState()
  if (state.mode === 'demo') return Promise.reject(new Error('SSO is unavailable in the synthetic demo'))
  if (pendingSsoExchange && pendingSsoSession !== state.session) return Promise.reject(new Error('Sign-in was interrupted; start again'))
  if (!pendingSsoExchange) {
    pendingSsoSession = state.session
    pendingSsoExchange = client.post<LoginResponse>('/auth/sso/session', undefined, {
      withCredentials: true,
      headers: { 'X-SSO-CSRF': '1' },
    }).then(({ data }) => {
      if (!data || typeof data.access_token !== 'string' || !data.access_token.trim() || typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer' || !data.user || data.user.is_active !== true || typeof data.user.user_id !== 'string' || !data.user.user_id || typeof data.user.username !== 'string' || !data.user.username || !['admin', 'analyst', 'viewer'].includes(data.user.role)) {
        throw new Error('Invalid SSO session response')
      }
      return data
    }).finally(() => { pendingSsoExchange = null; pendingSsoSession = null })
  }
  return pendingSsoExchange
}

export async function logout(): Promise<void> { await client.post('/auth/logout') }
export async function getMe(): Promise<User> {
  const { data } = await client.get<User>('/auth/me')
  return data
}
