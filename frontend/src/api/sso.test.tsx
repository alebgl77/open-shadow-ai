// @vitest-environment jsdom
import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import Login from '@/pages/Login'
import SsoCallback from '@/pages/SsoCallback'
import client from './client'
import { exchangeSsoSession, parseAuthProviders, SSO_FAILURE_MESSAGE, SSO_LOGIN_PATH, type LoginResponse } from './auth'
import { queryClient } from './query-client'
import { useAuthStore } from '@/stores/auth'

const provider = { local_enabled: true, sso: { enabled: true, label: 'Company identity', login_url: SSO_LOGIN_PATH } }
const disabled = { local_enabled: true, sso: { enabled: false, label: 'Single sign-on', login_url: SSO_LOGIN_PATH } }
const session: LoginResponse = { access_token: 'trusted-session-token', token_type: 'bearer', user: { user_id: 'sso-user', username: 'SSO analyst', email: 'analyst@example.test', role: 'analyst', is_active: true } }
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((yes,no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
function LocationProbe() {
  const location = useLocation()
  return <output data-testid="route">{location.pathname}{location.search}{location.hash}</output>
}
function renderAuth(path: string) {
  return render(<StrictMode><QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[path]}><Routes><Route path="/login" element={<Login/>}/><Route path="/auth/callback" element={<SsoCallback/>}/><Route path="/dashboard" element={<p>Workspace ready</p>}/></Routes><LocationProbe/></MemoryRouter></QueryClientProvider></StrictMode>)
}
beforeEach(() => { useAuthStore.getState().logout(); queryClient.clear() })
afterEach(() => { cleanup(); useAuthStore.getState().logout(); queryClient.clear(); vi.restoreAllMocks() })

describe('SSO provider discovery', () => {
  it('shows only discovered enabled SSO with an escaped provider label and preserves local sign-in', async () => {
    vi.spyOn(client,'get').mockResolvedValue({ data: { ...provider, sso: { ...provider.sso, label: '<script>Company</script>' } } })
    const view = renderAuth('/login')
    expect(await screen.findByRole('button',{name:'Continue with <script>Company</script>'})).toBeTruthy()
    expect(view.container.querySelector('script')).toBeNull()
    expect(screen.getByLabelText('Username')).toBeTruthy()
  })
  it.each([disabled, { local_enabled:true,sso:null }])('keeps local sign-in when SSO is disabled', async data => {
    const get=vi.spyOn(client,'get').mockResolvedValue({data})
    renderAuth('/login')
    await waitFor(()=>expect(get).toHaveBeenCalledOnce())
    await waitFor(()=>expect(screen.queryByText('Checking sign-in options…')).toBeNull())
    expect(screen.queryByRole('button',{name:/Continue with/})).toBeNull()
    expect(screen.getByLabelText('Username')).toBeTruthy()
  })
  it('shows metadata errors while local sign-in remains usable, and retries explicitly', async () => {
    const get=vi.spyOn(client,'get').mockRejectedValueOnce(new Error('Internal provider detail')).mockResolvedValue({data:provider})
    renderAuth('/login')
    expect((await screen.findByRole('alert')).textContent).toContain('Local account sign-in is still available')
    expect(screen.getByLabelText('Password')).toBeTruthy()
    expect(screen.queryByRole('button',{name:/Continue with/})).toBeNull()
    fireEvent.click(screen.getByRole('button',{name:'Check again'}))
    expect(await screen.findByRole('button',{name:'Continue with Company identity'})).toBeTruthy()
    expect(get).toHaveBeenCalledTimes(2)
  })
  it('renders a generic redirect failure without reflecting the URL error value', async () => {
    vi.spyOn(client,'get').mockResolvedValue({data:disabled})
    renderAuth('/login?sso_error=private-provider-error')
    expect(screen.getByRole('alert').textContent).toBe(SSO_FAILURE_MESSAGE)
    expect(screen.queryByText('private-provider-error')).toBeNull()
    await waitFor(()=>expect(screen.queryByText('Checking sign-in options…')).toBeNull())
  })
  it.each(['https://evil.test/login','//evil.test/login','/api/v1/auth/sso/login?next=evil','/api/v1/auth/sso/login#evil','\\evil.test','javascript:alert(1)'])('rejects untrusted navigation entry %s', login_url => {
    expect(()=>parseAuthProviders({...provider,sso:{...provider.sso,login_url}})).toThrow('Invalid SSO entry point')
  })
})

describe('one-use SSO callback', () => {
  it('exchanges once under StrictMode, ignores URL tokens and uses the shared memory/cache boundary', async () => {
    const request=deferred<{data:LoginResponse}>()
    const post=vi.spyOn(client,'post').mockReturnValue(request.promise)
    const storage=vi.spyOn(Storage.prototype,'setItem')
    const previousSession=useAuthStore.getState().session
    queryClient.setQueryData(['private-evidence'],['prior-session-data'])
    renderAuth('/auth/callback?access_token=untrusted#id_token=also-untrusted')
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith('/auth/sso/session',undefined,{withCredentials:true,headers:{'X-SSO-CSRF':'1'}})
    await act(async()=>{ request.resolve({data:session}); await request.promise })
    expect(await screen.findByText('Workspace ready')).toBeTruthy()
    expect(useAuthStore.getState()).toMatchObject({token:'trusted-session-token',mode:'live',isAuthenticated:true,session:previousSession+1})
    expect(queryClient.getQueryData(['private-evidence'])).toBeUndefined()
    expect(screen.getByTestId('route').textContent).toBe('/dashboard')
    expect(storage).not.toHaveBeenCalled()
  })
  it('handles an expired ticket without retrying or exposing provider error details', async () => {
    const post=vi.spyOn(client,'post').mockRejectedValue(new Error('Private upstream error'))
    vi.spyOn(client,'get').mockResolvedValue({data:disabled})
    renderAuth('/auth/callback')
    expect((await screen.findByRole('alert')).textContent).toBe(SSO_FAILURE_MESSAGE)
    expect(post).toHaveBeenCalledTimes(1)
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    fireEvent.click(screen.getByRole('link',{name:'Back to sign in'}))
    expect(await screen.findByLabelText('Username')).toBeTruthy()
    expect(screen.queryByText('Private upstream error')).toBeNull()
    await waitFor(()=>expect(screen.queryByText('Checking sign-in options…')).toBeNull())
  })
  it('does not apply a late response after the callback is abandoned for the demo', async () => {
    const request=deferred<{data:LoginResponse}>()
    vi.spyOn(client,'post').mockReturnValue(request.promise)
    const view=renderAuth('/auth/callback')
    view.unmount()
    useAuthStore.getState().enterDemo()
    await act(async()=>{ request.resolve({data:session}); await request.promise })
    expect(useAuthStore.getState()).toMatchObject({mode:'demo',token:null,user:{user_id:'demo-reviewer'}})
  })
  it('does not authenticate when sign-out invalidates the pending callback session', async () => {
    const request=deferred<{data:LoginResponse}>()
    vi.spyOn(client,'post').mockReturnValue(request.promise)
    renderAuth('/auth/callback')
    act(()=>useAuthStore.getState().logout())
    await act(async()=>{ request.resolve({data:session}); await request.promise })
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(useAuthStore.getState()).toMatchObject({isAuthenticated:false,token:null})
  })
  it('does not let a different session join an older pending exchange', async () => {
    const request=deferred<{data:LoginResponse}>()
    const post=vi.spyOn(client,'post').mockReturnValue(request.promise)
    const original=exchangeSsoSession()
    useAuthStore.getState().logout()
    await expect(exchangeSsoSession()).rejects.toThrow('interrupted')
    request.resolve({data:session}); await original
    expect(post).toHaveBeenCalledTimes(1)
  })
  it('rejects inactive returned users and never starts an exchange in demo mode', async () => {
    const post=vi.spyOn(client,'post').mockResolvedValue({data:{...session,user:{...session.user,is_active:false}}})
    await expect(exchangeSsoSession()).rejects.toThrow('Invalid SSO session response')
    useAuthStore.getState().enterDemo()
    await expect(exchangeSsoSession()).rejects.toThrow('unavailable in the synthetic demo')
    expect(post).toHaveBeenCalledTimes(1)
  })
})

describe('existing sign-in paths', () => {
  it('still signs in with a local account', async () => {
    vi.spyOn(client,'get').mockResolvedValue({data:disabled})
    const post=vi.spyOn(client,'post').mockResolvedValue({data:session})
    renderAuth('/login')
    fireEvent.change(screen.getByLabelText('Username'),{target:{value:'local-admin'}})
    fireEvent.change(screen.getByLabelText('Password'),{target:{value:'local-password'}})
    fireEvent.click(screen.getByRole('button',{name:'Sign in to workspace'}))
    expect(await screen.findByText('Workspace ready')).toBeTruthy()
    expect(post).toHaveBeenCalledWith('/auth/login',{username:'local-admin',password:'local-password'})
  })
  it('still enters the explicitly labeled demo without using SSO or persisting credentials', async () => {
    vi.spyOn(client,'get').mockResolvedValue({data:provider})
    const post=vi.spyOn(client,'post')
    renderAuth('/login')
    fireEvent.click(screen.getByRole('button',{name:'Explore the demo'}))
    expect(await screen.findByText('Workspace ready')).toBeTruthy()
    expect(useAuthStore.getState()).toMatchObject({mode:'demo',token:null})
    expect(post).not.toHaveBeenCalled()
  })
})
