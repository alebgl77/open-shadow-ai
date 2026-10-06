// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosError, AxiosHeaders } from 'axios'
import client from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { demoRequest } from '@/api/demo'
import type { CollectorHealth, PipelineHealth } from '@/api/operations'
import type { Detection } from '@/api/detections'
import Sources from './Sources'
import DetectionDetail from './DetectionDetail'

const admin = { user_id: 'ops-admin', username: 'administrator', email: null, role: 'admin' as const, is_active: true }
const health: CollectorHealth = {
  collector_id: 'sensor-one', display_name: 'Synthetic sensor', allowed_source_types: ['network'], status: 'quiet',
  last_server_contact_at: '2026-10-06T12:00:00Z', last_heartbeat_at: '2026-10-06T12:00:00Z', last_observed_at: '2026-10-02T12:00:00Z', server_contact_fresh: true,
  client_reported: { provenance: 'client_reported', as_of: '2026-10-06T12:00:00Z', fresh: true, queue_events: 12, queued_bytes: 1200, dropped_events: null, expired_events: 0, rejected_events: 1, last_success_at: null }, capture_loss: null,
}
const queues: PipelineHealth = { scope: 'deployment', as_of: '2026-10-06T12:00:00Z', backend_available: true, capture_loss: null, stages: [{ stage: 'ingest', group: 'ingest_group', status: 'blocked', deadletter_retained: 2, streams: [{ stream: 'events:network', status: 'blocked', group_present: true, retained_entries: 99, pending: 3, undelivered: null, oldest_pending_age_seconds: 700, worker_state_fresh: true, last_worker_seen_at: '2026-10-06T12:00:00Z', last_poll_at: null, last_progress_at: null, last_failure_at: '2026-10-06T12:00:00Z', counters_since: '2026-10-06T11:00:00Z', counters: { acknowledged: 5, retryable_failures: 6, rejected_attempts: 1, deadlettered: 2, replayed: 1 } }] }] }
const clients: QueryClient[] = []
const forbidden = () => new AxiosError('Forbidden', '403', undefined, undefined, { status: 403, statusText: 'Forbidden', data: {}, headers: {}, config: { headers: new AxiosHeaders() } })
let item: CollectorHealth
function serve() {
  return vi.spyOn(client, 'get').mockImplementation(async url => {
    if (url === '/dashboard/source-health') return { data: [] }
    if (url?.startsWith('/operations/collectors')) return { data: { items: [item], total: 1, offset: 0, limit: 50, as_of: '2026-10-06T12:00:00Z' } }
    if (url?.startsWith('/collectors?')) return { data: { items: [{ ...item, is_active: item.status !== 'revoked', revoked_at: item.status === 'revoked' ? '2026-10-06T12:00:00Z' : null }], total: 1, offset: 0, limit: 50 } }
    if (url === '/operations/pipeline') return { data: queues }
    throw new Error('Unexpected request')
  })
}
function mount(path = '/sources') {
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  clients.push(queries)
  return { queries, ...render(<QueryClientProvider client={queries}><MemoryRouter initialEntries={[path]}><Routes><Route path="/sources" element={<Sources/>}/><Route path="/discoveries/:id" element={<DetectionDetail/>}/></Routes></MemoryRouter></QueryClientProvider>) }
}
async function enrollment() {
  fireEvent.click(await screen.findByRole('button', { name: 'Enroll collector' }))
  fireEvent.change(screen.getByLabelText('Collector ID'), { target: { value: 'new-sensor' } })
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'New sensor' } })
  fireEvent.change(screen.getByLabelText('Key validity (days)'), { target: { value: '7' } })
  fireEvent.click(screen.getByRole('checkbox', { name: 'endpoint' }))
  fireEvent.click(screen.getByRole('checkbox', { name: 'network' }))
  fireEvent.click(screen.getByRole('button', { name: 'Create collector and key' }))
}
beforeEach(() => { item = structuredClone(health); localStorage.clear(); sessionStorage.clear(); useAuthStore.getState().login('csrf-ops', admin) })
afterEach(() => { cleanup(); clients.splice(0).forEach(query => query.clear()); useAuthStore.getState().logout(); vi.restoreAllMocks() })

describe('collector operations', () => {
  it('analysts read tenant collector health with advisory counts and no privileged calls', async () => {
    useAuthStore.getState().login('csrf-analyst', { ...admin, role: 'analyst' })
    const get = serve()
    mount()
    expect(await screen.findByText('Synthetic sensor')).toBeTruthy()
    expect(screen.getByText('quiet')).toBeTruthy()
    expect(screen.getByText(/Client counters are advisory. Capture loss is unknown/)).toBeTruthy()
    expect(screen.getByText(/A quiet source or replay can cause this/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Enroll collector' })).toBeNull()
    expect(screen.queryByRole('region', { name: 'Deployment pipeline' })).toBeNull()
    expect(get.mock.calls.some(([url]) => String(url).startsWith('/collectors?') || url === '/operations/pipeline')).toBe(false)
  })

  it('viewers do not fetch collector or deployment operational data', async () => {
    useAuthStore.getState().login('csrf-viewer', { ...admin, role: 'viewer' })
    const get = serve()
    mount()
    expect(screen.getByText(/Collector operational health requires/)).toBeTruthy()
    await waitFor(() => expect(get).toHaveBeenCalled())
    expect(get.mock.calls.every(([url]) => url === '/dashboard/source-health')).toBe(true)
  })

  it('enrolls selected sources and shows a key once outside all caches and storage', async () => {
    serve()
    const key = 'one-time-enrollment-private-key'
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: { api_key: key, expires_at: '2026-10-13T12:00:00Z' } })
    const { queries } = mount()
    await waitFor(() => expect((screen.getByRole('button', { name: 'Enroll collector' }) as HTMLButtonElement).disabled).toBe(false))
    await enrollment()
    expect((await screen.findByLabelText('One-time API key') as HTMLTextAreaElement).value).toBe(key)
    expect(post).toHaveBeenCalledWith('/collectors', { collector_id: 'new-sensor', display_name: 'New sensor', allowed_source_types: ['network'], expires_in_days: 7 })
    expect(JSON.stringify(queries.getQueryCache().getAll().map(query => query.state.data))).not.toContain(key)
    expect(queries.getMutationCache().getAll()).toHaveLength(0)
    expect(JSON.stringify(localStorage) + JSON.stringify(sessionStorage) + location.href).not.toContain(key)
    fireEvent.click(screen.getByRole('button', { name: 'Close credential dialog' }))
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Enroll collector' }))
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
  })

  it('rotates with explicit overlap and revokes only after confirmation', async () => {
    serve()
    const post = vi.spyOn(client, 'post').mockImplementation(async url => {
      if (url?.endsWith('/revoke')) { item.status = 'revoked'; return { data: item } }
      return { data: { api_key: 'replacement-key-once', expires_at: '2026-10-13T12:00:00Z', previous_valid_until: '2026-10-06T12:00:30Z' } }
    })
    mount()
    const rotate = await screen.findByRole('button', { name: 'Rotate key for sensor-one' })
    await waitFor(() => expect((rotate as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(rotate)
    fireEvent.change(screen.getByLabelText('Existing key overlap (seconds)'), { target: { value: '30' } })
    fireEvent.change(screen.getByLabelText('Key validity (days)'), { target: { value: '7' } })
    fireEvent.click(screen.getByRole('button', { name: 'Issue replacement key' }))
    expect((await screen.findByLabelText('One-time API key') as HTMLTextAreaElement).value).toBe('replacement-key-once')
    expect(post).toHaveBeenCalledWith('/collectors/sensor-one/rotate', { overlap_seconds: 30, expires_in_days: 7 })
    fireEvent.click(screen.getByRole('button', { name: 'Close credential dialog' }))
    fireEvent.click(screen.getByRole('button', { name: 'Revoke sensor-one' }))
    expect(post.mock.calls.some(([url]) => String(url).endsWith('/revoke'))).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revocation' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/collectors/sensor-one/revoke'))
    await screen.findByText('revoked')
    expect((screen.getByRole('button', { name: 'Rotate key for sensor-one' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('discards secrets and privileged queries on a role change within the same session', async () => {
    serve()
    vi.spyOn(client, 'post').mockResolvedValue({ data: { api_key: 'do-not-cache', expires_at: '2026-10-13T12:00:00Z' } })
    const { queries } = mount()
    await waitFor(() => expect((screen.getByRole('button', { name: 'Enroll collector' }) as HTMLButtonElement).disabled).toBe(false))
    await enrollment()
    await screen.findByLabelText('One-time API key')
    act(() => useAuthStore.setState({ user: { ...admin, role: 'analyst' } }))
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
    expect(screen.queryByRole('region', { name: 'Deployment pipeline' })).toBeNull()
    await waitFor(() => {
      const privileged = queries.getQueryCache().getAll().filter(query => ['collector-registry', 'pipeline-health'].includes(String(query.queryKey[0])))
      expect(privileged.some(query => query.queryKey[3] === 'admin')).toBe(false)
      expect(privileged.every(query => query.state.data === undefined)).toBe(true)
    })
  })

  it.each(['role', 'close', 'session'] as const)('drops a late credential response after %s change', async reason => {
    serve()
    let answer: (value: unknown) => void = () => undefined
    vi.spyOn(client, 'post').mockReturnValue(new Promise(resolve => { answer = resolve }))
    mount()
    await waitFor(() => expect((screen.getByRole('button', { name: 'Enroll collector' }) as HTMLButtonElement).disabled).toBe(false))
    await enrollment()
    if (reason === 'close') fireEvent.click(screen.getByRole('button', { name: 'Close credential dialog' }))
    else if (reason === 'role') act(() => useAuthStore.setState({ user: { ...admin, role: 'analyst' } }))
    else act(() => useAuthStore.getState().login('new-session', { ...admin, user_id: 'different-user' }))
    await act(async () => answer({ data: { api_key: 'late-secret', expires_at: '2026-10-13T12:00:00Z' } }))
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
    expect(document.body.textContent).not.toContain('late-secret')
  })

  it('shows unknown lag separately from retained entries and replaces cached stats on outage', async () => {
    const get = serve()
    const { queries } = mount()
    const region = await screen.findByRole('region', { name: 'Deployment pipeline' })
    await within(region).findByText('ingest · blocked')
    const row = within(region).getByText('events:network').closest('tr')!
    expect(row.children[1].textContent).toBe('3')
    expect(row.children[2].textContent).toBe('Unknown')
    expect(row.children[3].textContent).toBe('99')
    get.mockRejectedValue(new Error('offline'))
    await act(async () => { await queries.invalidateQueries() })
    expect(await screen.findByText(/Deployment queue state is unavailable/)).toBeTruthy()
    expect(screen.queryByText('events:network')).toBeNull()
    expect(screen.queryByText('Synthetic sensor')).toBeNull()
    expect(screen.queryByText(/No enrolled collectors/)).toBeNull()
  })

  it('does not show a credential from a failed action or echo the error body', async () => {
    serve()
    vi.spyOn(client, 'post').mockRejectedValue({ response: { data: { api_key: 'error-secret' } } })
    mount()
    await waitFor(() => expect((screen.getByRole('button', { name: 'Enroll collector' }) as HTMLButtonElement).disabled).toBe(false))
    await enrollment()
    expect((await screen.findByRole('alert')).textContent).toContain('lost response may follow a completed change')
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
    expect(document.body.textContent).not.toContain('error-secret')
  })

  it('clears an already displayed key when server permission is withdrawn', async () => {
    const get = serve()
    vi.spyOn(client, 'post').mockResolvedValue({ data: { api_key: 'formerly-authorized-key', expires_at: '2026-10-13T12:00:00Z' } })
    const { queries } = mount()
    await waitFor(() => expect((screen.getByRole('button', { name: 'Enroll collector' }) as HTMLButtonElement).disabled).toBe(false))
    await enrollment()
    await screen.findByLabelText('One-time API key')
    const forbidden = new AxiosError('Forbidden', '403', undefined, undefined, { status: 403, statusText: 'Forbidden', data: {}, headers: {}, config: { headers: new AxiosHeaders() } })
    get.mockRejectedValue(forbidden)
    await act(async () => { await queries.invalidateQueries() })
    await screen.findByText(/Collector administration is unavailable/)
    await waitFor(() => expect(screen.queryByLabelText('One-time API key')).toBeNull())
    expect(screen.queryByText('Synthetic sensor')).toBeNull()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Enroll collector' })).toBeNull()
    expect(JSON.stringify(queries.getQueryCache().getAll().map(query => query.state.data))).not.toContain('Synthetic sensor')
  })

  it('drops a late key after server denial despite unchanged local admin role/session', async () => {
    const get = serve()
    let answer: (value: unknown) => void = () => undefined
    vi.spyOn(client, 'post').mockReturnValue(new Promise(resolve => { answer = resolve }))
    const { queries } = mount()
    await waitFor(() => expect((screen.getByRole('button', { name: 'Enroll collector' }) as HTMLButtonElement).disabled).toBe(false))
    await enrollment()
    const forbidden = new AxiosError('Forbidden', '403', undefined, undefined, { status: 403, statusText: 'Forbidden', data: {}, headers: {}, config: { headers: new AxiosHeaders() } })
    get.mockRejectedValue(forbidden)
    await act(async () => { await queries.invalidateQueries() })
    await screen.findByText(/Collector administration is unavailable/)
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await act(async () => answer({ data: { api_key: 'late-denied-key', expires_at: '2026-10-13T12:00:00Z' } }))
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
    expect(document.body.textContent).not.toContain('late-denied-key')
    expect(useAuthStore.getState().user?.role).toBe('admin')
  })

  it('keeps denial through cache removal, failed revalidation and analyst health until a fresh authorized registry proves recovery', async () => {
    const get = serve()
    const authorized = get.getMockImplementation()!
    vi.spyOn(client, 'post').mockResolvedValue({ data: { api_key: 'discard-on-denial', expires_at: '2026-10-13T12:00:00Z' } })
    const { queries } = mount()
    await screen.findByRole('button', { name: 'Enroll collector' })
    await enrollment()
    await screen.findByLabelText('One-time API key')
    get.mockRejectedValue(forbidden())
    await act(async () => { await queries.invalidateQueries() })
    await screen.findByText(/Access was denied/)
    const session = useAuthStore.getState().session
    act(() => {
      queries.removeQueries({ queryKey: ['collector-registry'] })
      queries.removeQueries({ queryKey: ['pipeline-health'] })
      useAuthStore.setState({ csrfToken: 'same-session-refresh' })
    })
    expect(screen.queryByRole('button', { name: 'Enroll collector' })).toBeNull()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryByText('Synthetic sensor')).toBeNull()
    get.mockImplementation(async url => {
      if (url?.startsWith('/operations/collectors')) return authorized(url)
      throw new Error('Cannot confirm administrator authority')
    })
    // A successful analyst endpoint is deliberately not an admin proof.
    await act(async () => {
      try { await queries.fetchQuery({ queryKey: ['collector-health', 'live', session, 'admin', 0] }) } catch { /* canceled by the denial epoch */ }
    })
    expect(screen.queryByRole('button', { name: 'Enroll collector' })).toBeNull()
    let failedRefresh = false
    get.mockImplementation(async () => { failedRefresh = true; throw new Error('offline') })
    fireEvent.click(screen.getByRole('button', { name: 'Refresh administration access' }))
    await waitFor(() => expect(failedRefresh).toBe(true))
    expect(screen.queryByRole('button', { name: 'Enroll collector' })).toBeNull()
    get.mockImplementation(authorized)
    fireEvent.click(screen.getByRole('button', { name: 'Refresh administration access' }))
    expect(await screen.findByRole('button', { name: 'Enroll collector' })).toBeTruthy()
    expect(await screen.findByText('Synthetic sensor')).toBeTruthy()
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
    expect(useAuthStore.getState().session).toBe(session)
    expect(JSON.stringify(queries.getQueryCache().getAll().map(query => query.state.data))).not.toContain('discard-on-denial')
    expect(queries.getMutationCache().getAll()).toHaveLength(0)
    expect(JSON.stringify(localStorage) + JSON.stringify(sessionStorage)).not.toContain('discard-on-denial')
  })

  it('cannot regain authority from an authorized registry response that began before denial', async () => {
    const get = serve()
    const authorized = get.getMockImplementation()!
    const { queries } = mount()
    await screen.findByRole('button', { name: 'Enroll collector' })
    let answer: (value: unknown) => void = () => undefined
    let requested = false
    get.mockImplementation(async url => {
      if (url?.startsWith('/collectors?')) {
        requested = true
        return new Promise(resolve => { answer = resolve })
      }
      return authorized(url)
    })
    void queries.invalidateQueries({ queryKey: ['collector-registry'] })
    await waitFor(() => expect(requested).toBe(true))
    get.mockRejectedValue(forbidden())
    await act(async () => { await queries.invalidateQueries({ queryKey: ['collector-health'] }) })
    await screen.findByText(/Access was denied/)
    await act(async () => { answer(await authorized('/collectors?offset=0&limit=50')) })
    expect(screen.queryByRole('button', { name: 'Enroll collector' })).toBeNull()
    expect(screen.queryByText('Synthetic sensor')).toBeNull()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(JSON.stringify(queries.getQueryCache().getAll().map(query => query.state.data))).not.toContain('Synthetic sensor')
  })

  it.each(['enroll', 'rotate', 'revoke'] as const)('latches a %s mutation denial and discards privileged cache and credentials', async action => {
    const get = serve()
    const post = vi.spyOn(client, 'post').mockRejectedValue(forbidden())
    const { queries } = mount()
    await screen.findByRole('button', { name: 'Enroll collector' })
    get.mockRejectedValue(forbidden())
    if (action === 'enroll') await enrollment()
    else if (action === 'rotate') {
      fireEvent.click(screen.getByRole('button', { name: 'Rotate key for sensor-one' }))
      fireEvent.click(screen.getByRole('button', { name: 'Issue replacement key' }))
    } else {
      fireEvent.click(screen.getByRole('button', { name: 'Revoke sensor-one' }))
      fireEvent.click(screen.getByRole('button', { name: 'Confirm revocation' }))
    }
    await screen.findByText(/Access was denied/)
    expect(post).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('button', { name: 'Enroll collector' })).toBeNull()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryByLabelText('One-time API key')).toBeNull()
    expect(screen.queryByText('Synthetic sensor')).toBeNull()
    expect(JSON.stringify(queries.getQueryCache().getAll().map(query => query.state.data))).not.toContain('Synthetic sensor')
    expect(queries.getMutationCache().getAll()).toHaveLength(0)
  })

  it('keeps operational administration disabled in explicit demo simulation', () => {
    useAuthStore.getState().enterDemo()
    vi.spyOn(client, 'get').mockImplementation(async url => ({ data: demoRequest('get', url || '/') }))
    mount()
    expect(screen.getByText(/Simulation only. Live collector administration/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Enroll collector' })).toBeNull()
  })

  it('shows retained membership projection time separately from materialized risk time', async () => {
    const original = demoRequest('get', '/detections/demo-1') as Detection
    const detection = { ...original, risk_score_stale: true, risk_calculated_at: '2026-10-01T10:00:00Z', updated_at: '2026-10-06T12:00:00Z', evidence_bundle: { _identity_window: { days: 30, as_of: '2026-10-06T11:00:00Z' } } }
    vi.spyOn(client, 'get').mockImplementation(async url => ({ data: url?.endsWith('/timeline') ? [] : detection }))
    mount('/discoveries/demo-1')
    const window = await screen.findByLabelText('Identity retention window')
    expect(window.textContent).toContain('Observed membership retained for 30 days')
    expect(window.textContent).toContain(new Date('2026-10-06T11:00:00Z').toLocaleString())
    expect(screen.getByText(/Last risk calculation:/).textContent).toContain(new Date('2026-10-01T10:00:00Z').toLocaleString())
    expect(screen.getByText(/Count projection and note updates do not recalculate risk/)).toBeTruthy()
    expect(screen.getByText(/Retained membership may have changed/)).toBeTruthy()
  })
})
