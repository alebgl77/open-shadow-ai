import axios from 'axios'
import client from './client'
import { useAuthStore, type User } from '@/stores/auth'

export interface LoginResponse {
  access_token: string | null
  token_type: 'bearer' | 'cookie'
  csrf_token: string | null
  user: User
}
/** A browser session: the token stays in an HttpOnly cookie, scripts only see the CSRF token. */
export interface CookieSession {
  csrf_token: string
  user: User
}
function cookieSession(value: unknown, message: string): CookieSession {
  const data = value as Partial<LoginResponse> | null
  const user = data?.user
  if (!data || data.token_type !== 'cookie' || data.access_token || typeof data.csrf_token !== 'string' || !data.csrf_token.trim() || !user || user.is_active !== true || typeof user.user_id !== 'string' || !user.user_id || typeof user.username !== 'string' || !user.username || !['admin', 'analyst', 'viewer'].includes(user.role)) {
    throw new Error(message)
  }
  return { csrf_token: data.csrf_token, user }
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

export async function login(username: string, password: string): Promise<CookieSession> {
  const { data } = await client.post<LoginResponse>('/auth/login', { username, password }, { headers: { 'X-Session-Mode': 'cookie' } })
  return cookieSession(data, 'Invalid sign-in response')
}

/** Recover a cookie session after a reload; an unauthenticated visitor simply stays signed out. */
export async function restoreSession(): Promise<void> {
  const state = useAuthStore.getState()
  if (state.mode === 'demo' || state.isAuthenticated) { state.finishRestore(); return }
  const started = state.session
  try {
    const { data } = await client.get<LoginResponse>('/auth/session')
    const session = cookieSession(data, 'Invalid session response')
    // A sign-in or the demo started meanwhile owns the workspace now.
    if (useAuthStore.getState().session === started) useAuthStore.getState().login(session.csrf_token, session.user)
  } catch {
    if (useAuthStore.getState().session === started) useAuthStore.getState().finishRestore()
  }
}

// Share only the pending exchange across Strict Mode's setup/cleanup/setup cycle.
// A settled response is released; no ticket or token is kept in module storage.
let pendingSsoExchange: Promise<CookieSession> | null = null
let pendingSsoSession: number | null = null
export function exchangeSsoSession(): Promise<CookieSession> {
  const state = useAuthStore.getState()
  if (state.mode === 'demo') return Promise.reject(new Error('SSO is unavailable in the synthetic demo'))
  if (pendingSsoExchange && pendingSsoSession !== state.session) return Promise.reject(new Error('Sign-in was interrupted; start again'))
  if (!pendingSsoExchange) {
    pendingSsoSession = state.session
    pendingSsoExchange = client.post<LoginResponse>('/auth/sso/session', undefined, {
      withCredentials: true,
      headers: { 'X-SSO-CSRF': '1' },
    }).then(({ data }) => cookieSession(data, 'Invalid SSO session response'))
      .finally(() => { pendingSsoExchange = null; pendingSsoSession = null })
  }
  return pendingSsoExchange
}

// Only the server can delete the HttpOnly cookie: until this resolves, a reload restores the session.
// A 401 means the session had already ended. Any other failure rejects, so callers must not report a
// sign-out. The CSRF token is passed explicitly because callers clear the store right after.
export async function logout(csrfToken: string): Promise<void> {
  try {
    await client.post('/auth/logout', undefined, { headers: { 'X-CSRF-Token': csrfToken } })
  } catch (error) {
    if (!axios.isAxiosError(error) || error.response?.status !== 401) throw error
  }
}
export async function getMe(): Promise<User> {
  const { data } = await client.get<User>('/auth/me')
  return data
}
