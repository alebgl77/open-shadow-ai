// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosError, AxiosHeaders } from 'axios'
import client from '@/api/client'
import { demoRequest, resetDemo } from '@/api/demo'
import type { NetworkEvent, NetworkEvents, NetworkOverview } from '@/api/network'
import type { Detection } from '@/api/detections'
import { useAuthStore } from '@/stores/auth'
import Sidebar from '@/components/layout/Sidebar'
import Network from './Network'
import Sources from './Sources'
import DetectionDetail from './DetectionDetail'

const analyst = { user_id: 'network-analyst', username: 'analyst', email: null, role: 'analyst' as const, is_active: true }
const observation: NetworkEvent = {
  event_id: 'event-1', timestamp: '2026-10-06T10:00:00Z', protocol: 'QUIC', domain: 'research.example.test',
  sni: 'research.example.test', url_host: null, src_ip: '2001:db8:1::25', dst_ip: '2001:db8:2::10', dst_port: 443,
  collector_id: 'pilot-sensor', parser_version: 'metadata-1', matched: true, catalog_match_id: 'opaque-catalog-id',
}
const events: NetworkEvents = { items: [observation], total: 41, page: 1, page_size: 20 }
const overview: NetworkOverview = {
  hours: 24, total_observations: 6, named_observations: 5, matched_observations: 4, unmatched_observations: 2,
  protocols: { DNS: 2, TLS: 2, QUIC: 1, HTTP: 1 }, sensors: [{ collector_id: 'pilot-sensor', last_seen: observation.timestamp, observations: 6 }],
  limitations: ['Only imported metadata is counted.'],
}
const catalog = [{ catalog_item_id: 'opaque-catalog-id', canonical_name: 'Reviewed research service', category: 'code_assistant' }]
const clients: QueryClient[] = []

function LocationProbe() { const location = useLocation(); return <output aria-label="Current location">{location.pathname}{location.search}</output> }
function mount(path = '/network', sidebar = false) {
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  clients.push(queries)
  const result = render(<QueryClientProvider client={queries}><MemoryRouter initialEntries={[path]}>
    {sidebar && <Sidebar open onClose={() => undefined} />}
    <Routes><Route path="/network" element={<Network />} /><Route path="/sources" element={<Sources />} /><Route path="/discoveries/:id" element={<DetectionDetail />} /></Routes><LocationProbe />
  </MemoryRouter></QueryClientProvider>)
  return { ...result, queries }
}
function serve(overrides: { events?: NetworkEvents; overview?: NetworkOverview; catalog?: unknown[] } = {}) {
  return vi.spyOn(client, 'get').mockImplementation(async url => {
    if (url?.startsWith('/network/events')) return { data: overrides.events || events }
    if (url?.startsWith('/network/overview')) return { data: overrides.overview || overview }
    if (url?.startsWith('/catalog')) return { data: overrides.catalog || catalog }
    if (url === '/dashboard/source-health') return { data: [{ source_type: 'network', status: 'active', last_event: observation.timestamp, events_per_minute: .1 }] }
    throw new Error(`Unexpected request: ${url}`)
  })
}
function forbidden() { return new AxiosError('Forbidden', '403', undefined, undefined, { status: 403, statusText: 'Forbidden', data: {}, headers: {}, config: { headers: new AxiosHeaders() } }) }
beforeEach(() => { resetDemo(); useAuthStore.getState().login('csrf', analyst) })
afterEach(() => { cleanup(); clients.splice(0).forEach(query => query.clear()); useAuthStore.getState().logout(); vi.restoreAllMocks() })

describe('passive network console', () => {
  it('renders protocol totals, IPv6, dynamic service labels and bounded catalogue requests', async () => {
    const get = serve()
    mount()
    expect(await screen.findByText('Reviewed research service')).toBeTruthy()
    expect(screen.getByText('code assistant')).toBeTruthy()
    expect(screen.getByText('2001:db8:1::25')).toBeTruthy()
    expect(screen.getByText('[2001:db8:2::10]:443')).toBeTruthy()
    expect(screen.queryByText('opaque-catalog-id')).toBeNull()
    expect(screen.getByTitle('Passive network').querySelector('.bg-cyan-400')).toBeTruthy()
    const summary = screen.getByRole('region', { name: 'Network overview' })
    expect(within(summary).getByText('Imported observations').parentElement?.textContent).toContain('6')
    for (const [protocol, count] of Object.entries(overview.protocols)) {
      expect(within(summary).getByText(protocol).parentElement?.textContent).toBe(`${protocol}${count}`)
    }
    expect(screen.getByText('Status unknown')).toBeTruthy()
    expect(screen.getByText(/A lookup or connection is not proof of AI use/)).toBeTruthy()
    expect(get).toHaveBeenCalledWith('/catalog?page_size=500')
    expect(get).toHaveBeenCalledWith('/network/events?hours=24&page=1&page_size=20', expect.objectContaining({ signal: expect.any(AbortSignal) }))
  })

  it('keeps unmatched and nameless observations visible without inventing a service or ECH cause', async () => {
    serve({ events: { ...events, items: [{ ...observation, matched: false, catalog_match_id: null, domain: null, sni: null, dst_ip: null, dst_port: null }] } })
    mount()
    expect(await screen.findByText('Hostname not observed')).toBeTruthy()
    expect(screen.getByText('No catalog match')).toBeTruthy()
    expect(screen.getByText(/missing hostname has an unknown cause/)).toBeTruthy()
    expect(screen.queryByText('Reviewed research service')).toBeNull()
    expect(screen.queryByText(/ECH detected/)).toBeNull()
  })

  it('retains observed hostnames when catalogue labels are unavailable', async () => {
    const get = serve()
    get.mockImplementation(async url => {
      if (url?.startsWith('/catalog')) throw new Error('catalog offline')
      return { data: url?.startsWith('/network/events') ? events : overview }
    })
    mount()
    expect(await screen.findAllByText('research.example.test')).not.toHaveLength(0)
    expect(screen.getByText(/Service labels are unavailable/)).toBeTruthy()
    expect(screen.queryByText('opaque-catalog-id')).toBeNull()
    expect(screen.queryByText('Reviewed research service')).toBeNull()
  })

  it('shows an explicit permission state for viewers without fetching network metadata', () => {
    useAuthStore.getState().login('csrf-viewer', { ...analyst, role: 'viewer' })
    const get = serve()
    mount()
    expect(screen.getByRole('alert').textContent).toContain('analyst or administrator')
    expect(get).not.toHaveBeenCalled()
    expect(screen.queryByText(/No network observations/)).toBeNull()
  })

  it('replaces previously loaded observations with the permission state when the server returns 403', async () => {
    const get = serve()
    const { queries } = mount()
    await screen.findByText('Reviewed research service')
    get.mockRejectedValue(forbidden())
    await act(async () => { await queries.invalidateQueries() })
    expect((await screen.findByRole('alert')).textContent).toContain('analyst or administrator')
    expect(screen.queryByText('Reviewed research service')).toBeNull()
    expect(screen.queryByText('Imported observations')).toBeNull()
  })

  it('shows live failures without substituting demo or empty data, and retries explicitly', async () => {
    const get = serve()
    get.mockRejectedValue(new Error('offline'))
    mount()
    expect(await screen.findByText(/No sample data has been substituted/)).toBeTruthy()
    expect(screen.getByText(/No observation totals can be confirmed/)).toBeTruthy()
    expect(screen.queryByText(/Synthetic network observations/)).toBeNull()
    expect(screen.queryByText(/No network observations in this selection/)).toBeNull()
    expect(screen.queryByText('Imported observations')).toBeNull()
    expect(useAuthStore.getState().mode).toBe('live')
    get.mockImplementation(async url => ({ data: url?.startsWith('/network/events') ? events : url?.startsWith('/catalog') ? catalog : overview }))
    for (const button of screen.getAllByRole('button', { name: 'Retry' })) fireEvent.click(button)
    expect(await screen.findAllByText('research.example.test')).not.toHaveLength(0)
  })

  it('resets pagination and discards old rows while a changed protocol is loading', async () => {
    const get = serve({ events: { ...events, page: 3 } })
    const { queries } = mount('/network?hours=24&page=3')
    await screen.findByText('Reviewed research service')
    let answer: (value: unknown) => void = () => undefined
    get.mockReturnValueOnce(new Promise(resolve => { answer = resolve }))
    fireEvent.change(screen.getByRole('combobox', { name: 'Protocol' }), { target: { value: 'TLS' } })
    expect(screen.getByLabelText('Current location').textContent).toBe('/network?hours=24&page=1&protocol=TLS')
    expect(screen.getByText('Loading network observations…')).toBeTruthy()
    expect(screen.queryByText('Reviewed research service')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Next' })).toBeNull()
    await act(async () => { answer({ data: { ...events, items: [{ ...observation, domain: 'new.example.test', sni: null, catalog_match_id: null, protocol: 'TLS' }] } }) })
    expect(await screen.findByText('new.example.test')).toBeTruthy()
    expect(get).toHaveBeenCalledWith('/network/events?hours=24&page=1&page_size=20&protocol=TLS', expect.any(Object))
    const key = queries.getQueryCache().getAll().find(query => query.queryKey[0] === 'network-events' && JSON.stringify(query.queryKey).includes('TLS'))?.queryKey
    expect(key).toEqual(['network-events', 'live', useAuthStore.getState().session, { hours: 24, protocol: 'TLS', page: 1, page_size: 20 }])
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(screen.getByLabelText('Current location').textContent).toContain('page=2'))
    fireEvent.change(screen.getByRole('combobox', { name: 'Observation window' }), { target: { value: '72' } })
    expect(screen.getByLabelText('Current location').textContent).toContain('hours=72&page=1')
  })

  it('normalizes unsupported URL filters before issuing requests', async () => {
    const get = serve()
    mount('/network?hours=999&protocol=SMTP&page=-8')
    await screen.findByText('Reviewed research service')
    expect(get).toHaveBeenCalledWith('/network/events?hours=24&page=1&page_size=20', expect.any(Object))
    expect(screen.getByRole('combobox', { name: 'Protocol' }).getAttribute('value')).toBeNull()
    expect((screen.getByRole('combobox', { name: 'Protocol' }) as HTMLSelectElement).value).toBe('')
  })

  it('renders empty results and unknown sensor coverage without claiming zero activity', async () => {
    serve({ events: { items: [], total: 0, page: 1, page_size: 20 }, overview: { ...overview, total_observations: 0, named_observations: 0, matched_observations: 0, unmatched_observations: 0, sensors: [], protocols: { DNS: 0, TLS: 0, QUIC: 0, HTTP: 0 } } })
    mount()
    expect(await screen.findByText('No network observations in this selection')).toBeTruthy()
    expect(screen.getByText('No sensor observations in this window.')).toBeTruthy()
    expect(screen.getByText(/does not establish the absence/)).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Next' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('does not let a late live response overwrite a newly entered demo session', async () => {
    let answer: (value: unknown) => void = () => undefined
    const pending = new Promise(resolve => { answer = resolve })
    vi.spyOn(client, 'get').mockImplementation(async url => {
      if (useAuthStore.getState().mode === 'demo') return { data: demoRequest('get', url || '/') }
      return url?.startsWith('/network/events') ? pending : { data: url?.startsWith('/catalog') ? catalog : overview }
    })
    mount()
    await screen.findByText('Loading network observations…')
    await act(async () => { useAuthStore.getState().enterDemo() })
    expect(await screen.findAllByText('Claude')).not.toHaveLength(0)
    await act(async () => { answer({ data: { ...events, items: [{ ...observation, domain: 'late-live.example.test', catalog_match_id: null }] } }) })
    expect(screen.queryByText('late-live.example.test')).toBeNull()
    expect(screen.getByText(/Synthetic network observations/)).toBeTruthy()
  })

  it('uses the real demo adapter for deterministic network pagination and protocol filters', async () => {
    useAuthStore.getState().enterDemo()
    mount()
    expect(await screen.findAllByText('Claude')).not.toHaveLength(0)
    expect(screen.getByText('28 observations · page 1 of 2')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('28 observations · page 2 of 2')).toBeTruthy()
    fireEvent.change(screen.getByRole('combobox', { name: 'Protocol' }), { target: { value: 'QUIC' } })
    expect(await screen.findByText('7 observations · page 1 of 1')).toBeTruthy()
    const table = screen.getByRole('table')
    expect(within(table).queryByText('TLS')).toBeNull()
    expect(within(table).getAllByText('QUIC')).toHaveLength(7)
  })
})

describe('network integration with source and detection views', () => {
  it.each(['live', 'demo'] as const)('preserves the %s session through source and sidebar links', async mode => {
    if (mode === 'demo') useAuthStore.getState().enterDemo()
    else serve()
    const session = useAuthStore.getState()
    mount('/sources', true)
    const link = await screen.findByRole('link', { name: 'Inspect network observations' })
    expect(link.getAttribute('href')).toBe('/network')
    expect(screen.getByRole('link', { name: 'Network' }).getAttribute('href')).toBe('/network')
    fireEvent.click(link)
    expect(await screen.findByRole('heading', { name: 'Network observations' })).toBeTruthy()
    expect(useAuthStore.getState()).toBe(session)
    expect(screen.getByLabelText('Current location').textContent).toBe('/network')
  })

  it('renders structured network evidence safely and preserves other string samples', async () => {
    const original = demoRequest('get', '/detections/demo-1') as Detection
    const samples = Array.from({ length: 11 }, (_, index) => ({ ...observation, event_id: `sample-${index}`, domain: index === 0 ? '<img src=x onerror=alert(1)>' : `sample-${index}.example.test` }))
    const detection = { ...original, evidence_bundle: {
      network: { event_count: 11, confidence_base: .65, sample_values: ['plain-network-sample'], protocol_counts: { DNS: 3, TLS: 2, QUIC: 6, HTTP: 0 }, network_observations: samples },
      proxy: { event_count: 1, sample_values: ['unchanged-proxy-sample'] },
    } }
    vi.spyOn(client, 'get').mockImplementation(async url => ({ data: url?.endsWith('/timeline') ? [] : detection }))
    const { container } = mount('/discoveries/demo-1')
    const region = await screen.findByRole('region', { name: 'Network evidence' })
    expect(within(region).getByText('QUIC · <img src=x onerror=alert(1)>')).toBeTruthy()
    expect(container.querySelector('img')).toBeNull()
    expect(within(region).getAllByText('[2001:db8:2::10]:443')).toHaveLength(10)
    expect(screen.queryByText('sample-10.example.test')).toBeNull()
    expect(screen.getByText('plain-network-sample')).toBeTruthy()
    expect(screen.getByText('unchanged-proxy-sample')).toBeTruthy()
    expect(within(region).getByText('DNS').parentElement?.textContent).toBe('DNS3')
    expect(screen.getByRole('link', { name: 'Inspect network observations' }).getAttribute('href')).toBe('/network')
  })

  it('keeps safe detection summaries for viewers while withholding a supplied detailed network sample', async () => {
    useAuthStore.getState().login('csrf-viewer', { ...analyst, role: 'viewer' })
    const original = demoRequest('get', '/detections/demo-1') as Detection
    const detection = { ...original, evidence_bundle: {
      network: { event_count: 11, confidence_base: .65, sample_values: ['safe-summary.example.test'], protocol_counts: { DNS: 3, TLS: 2, QUIC: 6, HTTP: 0 }, network_observations: [{ ...observation, domain: 'sample-only.example.test', event_id: 'private-network-event', collector_id: 'private-network-sensor' }] },
    } }
    vi.spyOn(client, 'get').mockImplementation(async url => ({ data: url?.endsWith('/timeline') ? [] : detection }))
    mount('/discoveries/demo-1')
    const region = await screen.findByRole('region', { name: 'Network evidence' })
    expect(screen.getByText('safe-summary.example.test')).toBeTruthy()
    expect(screen.getByText('11 events')).toBeTruthy()
    expect(within(region).getByText('DNS').parentElement?.textContent).toBe('DNS3')
    expect(within(region).getByText('QUIC').parentElement?.textContent).toBe('QUIC6')
    expect(within(region).getByText('Detailed network observations are available to analysts and administrators.')).toBeTruthy()
    expect(screen.queryByText('No structured network sample retained.')).toBeNull()
    expect(screen.queryByText('Retained sample: up to 10 observations.')).toBeNull()
    for (const value of ['QUIC · sample-only.example.test', observation.src_ip!, '[2001:db8:2::10]:443', 'private-network-event', 'private-network-sensor']) expect(screen.queryByText(value)).toBeNull()
    expect(screen.queryByRole('link', { name: 'Inspect network observations' })).toBeNull()
  })

  it.each(['analyst', 'admin'] as const)('keeps the existing missing-sample state and inspection link for %s', async role => {
    useAuthStore.getState().login('csrf-reviewer', { ...analyst, role })
    const original = demoRequest('get', '/detections/demo-1') as Detection
    const detection = { ...original, evidence_bundle: { network: { event_count: 3, protocol_counts: { DNS: 3 } } } }
    vi.spyOn(client, 'get').mockImplementation(async url => ({ data: url?.endsWith('/timeline') ? [] : detection }))
    mount('/discoveries/demo-1')
    const region = await screen.findByRole('region', { name: 'Network evidence' })
    expect(within(region).getByText('No structured network sample retained.')).toBeTruthy()
    expect(within(region).getByText('Retained sample: up to 10 observations.')).toBeTruthy()
    expect(within(region).getByRole('link', { name: 'Inspect network observations' }).getAttribute('href')).toBe('/network')
    expect(screen.queryByText('Detailed network observations are available to analysts and administrators.')).toBeNull()
  })

  it('keeps demo counts consistent across protocol, match and sensor totals in every window', () => {
    const totals = [24, 72, 168].map(hours => {
      const summary = demoRequest('get', `/network/overview?hours=${hours}`) as NetworkOverview
      const records = demoRequest('get', `/network/events?hours=${hours}&page_size=100`) as NetworkEvents
      expect(Object.values(summary.protocols).reduce((sum, value) => sum + value, 0)).toBe(summary.total_observations)
      expect(summary.matched_observations + summary.unmatched_observations).toBe(summary.total_observations)
      expect(summary.sensors.reduce((sum, value) => sum + value.observations, 0)).toBe(summary.total_observations)
      expect(new Set(records.items.map(event => event.event_id)).size).toBe(summary.total_observations)
      expect(summary.named_observations).toBeLessThan(summary.total_observations)
      return summary.total_observations
    })
    expect(totals).toEqual([28, 31, 36])
  })
})
