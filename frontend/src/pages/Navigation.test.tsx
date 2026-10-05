// @vitest-environment jsdom
import { cleanup, createEvent, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import client from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import Extensions from './Extensions'
import OAuthApps from './OAuthApps'
import LocalAI from './LocalAI'

beforeEach(() => { useAuthStore.getState().logout() })
afterEach(() => { cleanup(); useAuthStore.getState().logout(); vi.restoreAllMocks() })

function Destination() {
  const location = useLocation()
  return <p>{location.pathname}{location.search}</p>
}

describe.each(['demo', 'live'] as const)('%s internal navigation', mode => {
  it.each([
    { Page: Extensions, path: '/extensions', destination: '/discoveries?entity_type=browser_extension', name: 'Open the complete paginated list' },
    { Page: OAuthApps, path: '/oauth', destination: '/discoveries?entity_type=oauth_app', name: 'Open the complete paginated list' },
    { Page: LocalAI, path: '/local-ai', destination: '/discoveries', name: 'Open Discoveries' },
  ])('keeps the session when leaving $path', async ({ Page, path, destination, name }) => {
    if (mode === 'demo') useAuthStore.getState().enterDemo()
    else useAuthStore.getState().login('live-csrf', { user_id: '1', username: 'analyst', email: null, role: 'analyst', is_active: true })
    const session = useAuthStore.getState()
    vi.spyOn(client, 'get').mockResolvedValue({ data: { items: [], total: 0, page: 1, page_size: 100 } })
    const queries = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={queries}><MemoryRouter initialEntries={[path]}><Routes>
      <Route path={path} element={<Page />} /><Route path="/discoveries" element={<Destination />} />
    </Routes></MemoryRouter></QueryClientProvider>)
    const link = screen.getByRole('link', { name })
    expect(link.getAttribute('href')).toBe(destination)
    const click = createEvent.click(link, { button: 0 })
    fireEvent(link, click)
    expect(click.defaultPrevented).toBe(true)
    expect(await screen.findByText(destination)).toBeTruthy()
    expect(useAuthStore.getState()).toBe(session)
  })
})
