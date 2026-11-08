// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import client from '@/api/client'
import { sourceHealthQueryOptions } from '@/api/dashboard'
import { useAuthStore } from '@/stores/auth'
import AppShell from './AppShell'

const listeners = new Set<() => void>()
const viewport = {
  matches: false,
  addEventListener: (_: string, callback: () => void) => listeners.add(callback),
  removeEventListener: (_: string, callback: () => void) => listeners.delete(callback),
}
const dialogProperties = Object.getOwnPropertyDescriptors(HTMLDialogElement.prototype)
const source = { source_type: 'dns', status: 'active', last_event: '2026-11-06T12:00:00Z', events_per_minute: 0.5 }

function setDesktop(value: boolean) {
  act(() => {
    viewport.matches = value
    listeners.forEach(callback => callback())
  })
}

function renderShell(children = <p>Overview content</p>) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={cache}><MemoryRouter initialEntries={['/dashboard']}>
    <AppShell><Routes>
      <Route path="/dashboard" element={children}/>
      <Route path="/discoveries" element={<p>Discoveries content</p>}/>
    </Routes></AppShell>
  </MemoryRouter></QueryClientProvider>)
  return cache
}

function openDrawer() {
  const trigger = screen.getByRole('button', { name: 'Open navigation' })
  trigger.focus()
  fireEvent.click(trigger)
  return { trigger, drawer: screen.getByRole('dialog', { name: 'Main navigation' }) }
}

beforeEach(() => {
  viewport.matches = false
  vi.stubGlobal('matchMedia', () => viewport)
  useAuthStore.getState().enterDemo()
  vi.spyOn(client, 'get').mockResolvedValue({ data: [source] })
  // jsdom lacks the dialog top layer. Native focus, Escape and backdrop behavior
  // are covered in the browser smoke check; this shim preserves the lifecycle.
  Object.defineProperties(HTMLDialogElement.prototype, {
    showModal: { configurable: true, value(this: HTMLDialogElement) { this.open = true } },
    close: { configurable: true, value(this: HTMLDialogElement) { this.open = false } },
  })
})

afterEach(() => {
  cleanup()
  listeners.clear()
  for (const name of ['showModal', 'close']) {
    if (dialogProperties[name]) Object.defineProperty(HTMLDialogElement.prototype, name, dialogProperties[name])
    else Reflect.deleteProperty(HTMLDialogElement.prototype, name)
  }
  useAuthStore.getState().logout()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('mobile navigation', () => {
  it('places focus inside, wraps Tab and restores the menu button on cancellation', () => {
    renderShell()
    const { drawer, trigger } = openDrawer()
    const close = within(drawer).getByRole('button', { name: 'Close navigation' })
    const last = within(drawer).getByRole('button', { name: 'Exit demo' })
    expect(document.activeElement).toBe(close)
    expect(fireEvent.keyDown(close, { key: 'Tab', shiftKey: true })).toBe(false)
    expect(document.activeElement).toBe(last)
    expect(fireEvent.keyDown(last, { key: 'Tab' })).toBe(false)
    expect(document.activeElement).toBe(close)
    fireEvent(drawer, new Event('cancel', { cancelable: true }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(trigger)
  })

  it('focuses the destination on link navigation and returns to the trigger after a backdrop dismissal', () => {
    renderShell()
    const { drawer, trigger } = openDrawer()
    fireEvent.click(drawer)
    expect(document.activeElement).toBe(trigger)
    const { drawer: reopened } = openDrawer()
    fireEvent.click(within(reopened).getByRole('link', { name: 'Discoveries' }))
    expect(screen.getByText('Discoveries content')).toBeTruthy()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('main'))
  })

  it('closes when moving to desktop and stays closed when returning to mobile', () => {
    renderShell()
    openDrawer()
    setDesktop(true)
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('navigation', { name: 'Main navigation' })).toBeTruthy()
    expect(document.activeElement).toBe(screen.getByRole('main'))
    setDesktop(false)
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('button', { name: 'Open navigation' }).getAttribute('aria-expanded')).toBe('false')
  })
})

function SourceReader() {
  const { mode, session } = useAuthStore()
  const query = useQuery(sourceHealthQueryOptions(mode, session))
  return <p>{query.data ? 'Coverage received' : 'Awaiting coverage'}</p>
}

it('shares coverage with page readers while keeping session changes isolated', async () => {
  const cache = renderShell(<SourceReader/>)
  const status = /^Recent sources: 1\. Events in the hour before the last check\.$/
  await screen.findByRole('link', { name: status })
  expect(screen.getByText('Coverage received')).toBeTruthy()
  expect(client.get).toHaveBeenCalledTimes(1)

  let finish = (_: { data: unknown[] }) => {}
  vi.mocked(client.get).mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
  act(() => useAuthStore.getState().login('live-csrf', {
    user_id: '1', username: 'analyst', email: null, role: 'analyst', is_active: true,
  }))
  expect(screen.queryByRole('link', { name: status })).toBeNull()
  expect(screen.getByRole('link', { name: 'Checking sources…' })).toBeTruthy()
  expect(screen.getByText('Awaiting coverage')).toBeTruthy()
  await waitFor(() => expect(client.get).toHaveBeenCalledTimes(2))
  finish({ data: [] })
  expect(await screen.findByRole('link', { name: /Recent sources: 0/ })).toBeTruthy()
  cache.clear()
})
