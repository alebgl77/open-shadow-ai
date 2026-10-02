// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import client from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import DemoEntry from './DemoEntry'

const analyst = { user_id: '1', username: 'analyst', email: null, role: 'analyst' as const, is_active: true }
beforeEach(() => { useAuthStore.getState().logout() })
afterEach(() => { cleanup(); useAuthStore.getState().logout(); vi.restoreAllMocks() })

function renderDemo() {
  return render(<MemoryRouter initialEntries={['/demo']}><Routes><Route path="/demo" element={<DemoEntry />} /><Route path="/dashboard" element={<p>Dashboard</p>} /></Routes></MemoryRouter>)
}

describe('demo entry', () => {
  it('keeps a live session until the user explicitly signs out', async () => {
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: {} })
    useAuthStore.getState().login('live-csrf', analyst)
    renderDemo()
    expect(screen.getByText(/signed in to your workspace/)).toBeTruthy()
    expect(useAuthStore.getState()).toMatchObject({ mode: 'live', csrfToken: 'live-csrf' })
    fireEvent.click(screen.getByRole('button', { name: 'Sign out and open the demo' }))
    expect(post).toHaveBeenCalledWith('/auth/logout', undefined, { headers: { 'X-CSRF-Token': 'live-csrf' } })
    expect(await screen.findByText('Dashboard')).toBeTruthy()
    expect(useAuthStore.getState()).toMatchObject({ mode: 'demo', csrfToken: null })
  })
  it('stays in the workspace when the server could not end the session', async () => {
    vi.spyOn(client, 'post').mockRejectedValue(new Error('offline'))
    useAuthStore.getState().login('live-csrf', analyst)
    renderDemo()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out and open the demo' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/still active/)
    expect(useAuthStore.getState()).toMatchObject({ mode: 'live', csrfToken: 'live-csrf', isAuthenticated: true })
  })
  it('opens directly when no live session exists', async () => {
    renderDemo()
    expect(await screen.findByText('Dashboard')).toBeTruthy()
    expect(useAuthStore.getState().mode).toBe('demo')
  })
})
