import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AxiosHeaders, type InternalAxiosRequestConfig } from 'axios'
import client from './client'
import { login, restoreSession } from './auth'
import { useAuthStore } from '@/stores/auth'

const user = { user_id: '1', username: 'analyst', email: null, role: 'analyst' as const, is_active: true }
const cookieSession = { access_token: null, token_type: 'cookie', csrf_token: 'csrf-1', user }
beforeEach(() => { useAuthStore.getState().logout(); useAuthStore.setState({ restoring: true }) })
afterEach(() => { vi.restoreAllMocks() })

function capture() {
  const seen: InternalAxiosRequestConfig[] = []
  const adapter = async (config: InternalAxiosRequestConfig) => { seen.push(config); return { data: {}, status: 200, statusText: 'OK', headers: new AxiosHeaders(), config } }
  return { seen, adapter }
}

describe('cookie session in the browser', () => {
  it('restores the profile and CSRF token after a reload', async () => {
    const get = vi.spyOn(client, 'get').mockResolvedValue({ data: cookieSession })
    await restoreSession()
    expect(get).toHaveBeenCalledWith('/auth/session')
    expect(useAuthStore.getState()).toMatchObject({ isAuthenticated: true, csrfToken: 'csrf-1', restoring: false, user: { username: 'analyst' } })
  })
  it('stays signed out without a session and never accepts a readable token', async () => {
    vi.spyOn(client, 'get').mockRejectedValueOnce(new Error('401')).mockResolvedValueOnce({ data: { ...cookieSession, access_token: 'leaked', token_type: 'bearer' } })
    await restoreSession()
    expect(useAuthStore.getState()).toMatchObject({ isAuthenticated: false, restoring: false })
    useAuthStore.setState({ restoring: true })
    await restoreSession()
    expect(useAuthStore.getState()).toMatchObject({ isAuthenticated: false, csrfToken: null })
    vi.spyOn(client, 'post').mockResolvedValue({ data: { ...cookieSession, access_token: 'leaked', token_type: 'bearer' } })
    await expect(login('analyst', 'password')).rejects.toThrow('Invalid sign-in response')
  })
  it('does not override the demo or a sign-in that started while restoring', async () => {
    let resolve!: (value: { data: unknown }) => void
    vi.spyOn(client, 'get').mockReturnValue(new Promise(done => { resolve = done }))
    const pending = restoreSession()
    useAuthStore.getState().enterDemo()
    resolve({ data: cookieSession })
    await pending
    expect(useAuthStore.getState()).toMatchObject({ mode: 'demo', csrfToken: null })
  })
  it('sends the CSRF token on writes only and never an Authorization header', async () => {
    useAuthStore.getState().login('csrf-1', user)
    const { seen, adapter } = capture()
    await client.get('/detections', { adapter })
    await client.post('/exports/detections', undefined, { adapter })
    await client.delete('/governance/x', { adapter })
    expect(seen[0].headers.has('X-CSRF-Token')).toBe(false)
    expect(seen[1].headers.get('X-CSRF-Token')).toBe('csrf-1')
    expect(seen[2].headers.get('X-CSRF-Token')).toBe('csrf-1')
    expect(seen.every(config => !config.headers.has('Authorization'))).toBe(true)
  })
})
