// @vitest-environment jsdom
import { AxiosError, AxiosHeaders } from 'axios'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import client from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import Sidebar from './Sidebar'

beforeEach(() => { useAuthStore.getState().logout() })
afterEach(() => { cleanup(); useAuthStore.getState().logout(); vi.restoreAllMocks() })

const analyst = { user_id: '1', username: 'analyst', email: null, role: 'analyst' as const, is_active: true }
function renderSidebar() {
  return render(<MemoryRouter initialEntries={['/dashboard']}><Routes><Route path="/dashboard" element={<Sidebar open onClose={() => undefined} />} /><Route path="/login" element={<p>Login page</p>} /></Routes></MemoryRouter>)
}
function httpError(status: number) {
  return new AxiosError('failed', String(status), undefined, undefined, { status, statusText: '', data: {}, headers: {}, config: { headers: new AxiosHeaders() } })
}

describe('sign-out', () => {
  it('leaves only once the server has revoked the session and deleted its cookie', async () => {
    let answer: (value: unknown) => void = () => undefined
    const post = vi.spyOn(client, 'post').mockReturnValue(new Promise(resolve => { answer = resolve }))
    useAuthStore.getState().login('live-csrf', analyst)
    renderSidebar()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(post).toHaveBeenCalledWith('/auth/logout', undefined, { headers: { 'X-CSRF-Token': 'live-csrf' } })
    // Until the server answers, the cookie is still valid: a reload would restore the session.
    expect(useAuthStore.getState().isAuthenticated).toBe(true)
    expect((screen.getByRole('button', { name: 'Sign out' }) as HTMLButtonElement).disabled).toBe(true)
    answer({ data: { message: 'logged out' } })
    expect(await screen.findByText('Login page')).toBeTruthy()
    expect(useAuthStore.getState()).toMatchObject({ csrfToken: null, isAuthenticated: false })
  })
  it('does not report a sign-out the server never confirmed', async () => {
    vi.spyOn(client, 'post').mockRejectedValue(new Error('offline'))
    useAuthStore.getState().login('live-csrf', analyst)
    renderSidebar()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/still active/)
    expect(useAuthStore.getState()).toMatchObject({ csrfToken: 'live-csrf', isAuthenticated: true })
    expect((screen.getByRole('button', { name: 'Sign out' }) as HTMLButtonElement).disabled).toBe(false)
  })
  it('treats an already ended session as signed out', async () => {
    vi.spyOn(client, 'post').mockRejectedValue(httpError(401))
    useAuthStore.getState().login('live-csrf', analyst)
    renderSidebar()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByText('Login page')).toBeTruthy()
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
  })
  it('refuses a sign-out the server rejected', async () => {
    vi.spyOn(client, 'post').mockRejectedValue(httpError(403))
    useAuthStore.getState().login('live-csrf', analyst)
    renderSidebar()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy())
    expect(useAuthStore.getState().isAuthenticated).toBe(true)
  })
  it('never calls the server to exit the demo', async () => {
    const post = vi.spyOn(client, 'post')
    useAuthStore.getState().enterDemo()
    renderSidebar()
    fireEvent.click(screen.getByRole('button', { name: 'Exit demo' }))
    expect(await screen.findByText('Login page')).toBeTruthy()
    expect(post).not.toHaveBeenCalled()
  })
})
