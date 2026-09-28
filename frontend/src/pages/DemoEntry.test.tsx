// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import client from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import DemoEntry from './DemoEntry'

const analyst = { user_id: '1', username: 'analyst', email: null, role: 'analyst' as const, is_active: true }
afterEach(() => { cleanup(); useAuthStore.getState().logout(); vi.restoreAllMocks() })

function renderDemo() {
  return render(<MemoryRouter initialEntries={['/demo']}><Routes><Route path="/demo" element={<DemoEntry />} /><Route path="/dashboard" element={<p>Dashboard</p>} /></Routes></MemoryRouter>)
}

describe('demo entry', () => {
  it('keeps a live session until the user explicitly signs out', async () => {
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: {} })
    useAuthStore.getState().login('live-token', analyst)
    renderDemo()
    expect(screen.getByText(/signed in to your workspace/)).toBeTruthy()
    expect(useAuthStore.getState()).toMatchObject({ mode: 'live', token: 'live-token' })
    fireEvent.click(screen.getByRole('button', { name: 'Sign out and open the demo' }))
    expect(post).toHaveBeenCalledWith('/auth/logout', undefined, { headers: { Authorization: 'Bearer live-token' } })
    expect(await screen.findByText('Dashboard')).toBeTruthy()
    expect(useAuthStore.getState()).toMatchObject({ mode: 'demo', token: null })
  })
  it('opens directly when no live session exists', async () => {
    renderDemo()
    expect(await screen.findByText('Dashboard')).toBeTruthy()
    expect(useAuthStore.getState().mode).toBe('demo')
  })
})
