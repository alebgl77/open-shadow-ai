// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import client from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import Sidebar from './Sidebar'

afterEach(() => { cleanup(); useAuthStore.getState().logout(); vi.restoreAllMocks() })

describe('sign-out', () => {
  it('revokes the server session with the token it is discarding', async () => {
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: { message: 'logged out' } })
    useAuthStore.getState().login('live-session-token', { user_id: '1', username: 'analyst', email: null, role: 'analyst', is_active: true })
    render(<MemoryRouter><Sidebar open onClose={() => undefined} /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(post).toHaveBeenCalledWith('/auth/logout', undefined, { headers: { Authorization: 'Bearer live-session-token' } })
    expect(useAuthStore.getState()).toMatchObject({ token: null, isAuthenticated: false })
  })
  it('still signs out locally when the server is unreachable, and never calls it in demo mode', async () => {
    const post = vi.spyOn(client, 'post').mockRejectedValue(new Error('offline'))
    useAuthStore.getState().login('live-session-token', { user_id: '1', username: 'analyst', email: null, role: 'analyst', is_active: true })
    const view = render(<MemoryRouter><Sidebar open onClose={() => undefined} /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    view.unmount()
    post.mockClear()
    useAuthStore.getState().enterDemo()
    render(<MemoryRouter><Sidebar open onClose={() => undefined} /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: 'Exit demo' }))
    expect(post).not.toHaveBeenCalled()
  })
})
