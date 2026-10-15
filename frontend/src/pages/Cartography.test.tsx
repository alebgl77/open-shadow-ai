// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosError, AxiosHeaders } from 'axios'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import client from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { LocaleProvider, LOCALE_STORAGE_KEY, createI18n } from '@/i18n'
import type { NetworkEvent, NetworkRelations } from '@/api/network'
import type { ExtensionInventoryItem } from '@/api/inventory'
import Cartography from './Cartography'
import Sidebar from '@/components/layout/Sidebar'

vi.mock('@/components/cartography/Scene', () => ({ default: ({ onUnavailable }: { onUnavailable: () => void }) => <button onClick={onUnavailable}>Simulate context loss</button> }))
const analyst = { user_id: 'cartographer', username: 'analyst', email: null, role: 'analyst' as const, is_active: true }
const stamp = '2026-10-15T01:00:00Z'
const relations: NetworkRelations = { hours: 24, protocol: null, items: [{ source_ip: '192.0.2.1', domain: 'ai.example.test', catalog_match_id: 'catalog-1', protocol: 'TLS', observations: 41, first_seen: stamp, last_seen: stamp }], total_observations: 41, total_relations: 1, represented_observations: 41, represented_relations: 1, truncated: false, limitations: ['Counts cover imported observations only; unobserved traffic and sensor outages are unknown.', '__proto__', 'Raw upstream evidence remains verbatim'] }
const event: NetworkEvent = { event_id: 'a17b83dd-ae12-4f1c-a911-c50ae4636c31', timestamp: stamp, protocol: 'TLS', domain: 'ai.example.test', src_ip: '192.0.2.1', dst_ip: '2001:db8::2', dst_port: 443, sni: 'ai.example.test', url_host: null, collector_id: 'collector-1', parser_version: 'metadata-1', matched: true, catalog_match_id: 'catalog-1', match_field: 'domain', match_confidence: .8 }
const service = { catalog_item_id: 'catalog-1', canonical_name: 'Reviewed service', category: 'code_assistant' }
const installation = { inventory_key: 'key-1', host_label: 'reported-host', collector_id: 'agent-1', browser: 'chrome', profile: 'Default', extension_id: 'ext-1', extension_name: 'Installed assistant', version: '1.2.3', enabled: null, install_source: 'store', present_in_latest_snapshot: true, first_seen_at: stamp, last_seen_at: stamp, catalog_item_id: 'catalog-1', detection_id: 'discovery-1', last_event_id: 'inventory-event-1' } as ExtensionInventoryItem
const clients: QueryClient[] = []
const relationWarnings = ['Source IPs are stored observations, not attributed devices; blank sources may reflect privacy erasure.', 'Relations are bounded and ordered by observation count; totals cover the full selected window.'] as const
function error(status: number) { return new AxiosError('PRIVATE_ERROR_MUST_NOT_RENDER', String(status), undefined, undefined, { data: {}, status, statusText: '', headers: {}, config: { headers: new AxiosHeaders() } }) }
function serve(installs: ExtensionInventoryItem[] = []) {
  return vi.spyOn(client, 'get').mockImplementation(async url => {
    if (url?.startsWith('/network/relations')) return { data: relations }
    if (url?.startsWith('/network/events/')) return { data: event }
    if (url?.startsWith('/network/events?')) return { data: { items: [event], total: 41, page: new URL(url, 'https://test.invalid').searchParams.get('page'), page_size: 20 } }
    if (url?.startsWith('/extensions/inventory?')) return { data: { items: installs, total: installs.length, identity_window: { days: 30, as_of: stamp }, identity_mode: 'pseudonymized' } }
    if (url?.startsWith('/catalog?')) return { data: [service] }
    if (url?.startsWith('/catalog/')) return { data: service }
    throw new Error('Unexpected request')
  })
}
function mount(sidebar = false) {
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } }); clients.push(queries)
  const result = render(<LocaleProvider><QueryClientProvider client={queries}><MemoryRouter>{sidebar && <Sidebar open onClose={() => {}}/>}<Cartography/></MemoryRouter></QueryClientProvider></LocaleProvider>)
  return { ...result, queries }
}
beforeEach(() => { localStorage.clear(); useAuthStore.getState().login('csrf', analyst) })
afterEach(() => { cleanup(); clients.splice(0).forEach(query => query.clear()); useAuthStore.getState().logout(); vi.restoreAllMocks() })

describe('cartography route evidence and permissions', () => {
  it('drills an exact relation into paginated observations and actual event provenance without a fake network discovery link', async () => {
    const get = serve(); mount()
    const detail = await screen.findByRole('complementary', { name: 'Evidence detail' })
    await within(detail).findByText(event.event_id)
    const url = get.mock.calls.map(([url]) => url).find(url => url?.startsWith('/network/events?'))!
    const params = new URL(url, 'https://test.invalid').searchParams
    expect(Object.fromEntries(params)).toEqual({ hours: '24', page: '1', page_size: '20', source_ip: '192.0.2.1', catalog_match_id: 'catalog-1', domain: 'ai.example.test', protocol: 'TLS' })
    fireEvent.click(within(detail).getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(get.mock.calls.some(([url]) => url?.includes('page=2'))).toBe(true))
    fireEvent.click(await within(detail).findByText(event.event_id))
    await within(detail).findByText('Stored association score')
    expect(within(detail).getByText('0.8')).toBeTruthy()
    expect(within(detail).getByText('metadata-1')).toBeTruthy()
    expect(within(detail).getByText('[2001:db8::2]:443')).toBeTruthy()
    expect(within(detail).getByText(/Source file and log line: not retained/)).toBeTruthy()
    expect(within(detail).queryByRole('link')).toBeNull()
    expect(get).toHaveBeenCalledWith(`/network/events/${event.event_id}?hours=24`, expect.objectContaining({ signal: expect.any(AbortSignal) }))
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(within(detail).queryByText('Stored association score')).toBeNull()
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('complementary', { name: 'Evidence detail' })).toBeNull()
  })
  it.each([404, 503])('renders a sanitized %s detail failure and retains the back action', async status => {
    const get = serve(); const original = get.getMockImplementation()!
    get.mockImplementation((url, config) => url?.startsWith('/network/events/') ? Promise.reject(error(status)) : original(url, config))
    mount(); fireEvent.click(await screen.findByText(event.event_id))
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain(status === 404 ? 'no longer available' : 'provenance is unavailable')
    expect(screen.queryByText('PRIVATE_ERROR_MUST_NOT_RENDER')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Back to relationship' }))
    expect(await screen.findByText(event.event_id)).toBeTruthy()
  })
  it('uses the accessible table and native node controls after WebGL context loss', async () => {
    serve(); mount(); await screen.findByText(event.event_id)
    fireEvent.click(screen.getByRole('button', { name: 'Simulate context loss' }))
    expect(screen.getByRole('status').textContent).toContain('3D is unavailable')
    expect(screen.getByRole('table')).toBeTruthy()
    fireEvent.click(screen.getByText('Select a node with the keyboard'))
    const source = screen.getAllByRole('button', { name: /192.0.2.1/ }).find(button => button.hasAttribute('aria-pressed'))!
    fireEvent.click(source)
    expect(source.getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByText('Connected relationships')).toBeTruthy()
  })
  it('shows only genuine installation evidence and links only a reported detection ID', async () => {
    serve([installation]); mount()
    const detail = await screen.findByRole('complementary', { name: 'Evidence detail' })
    expect(within(detail).getByRole('link', { name: 'Open discovery evidence' }).getAttribute('href')).toBe('/discoveries/discovery-1')
    expect(within(detail).getByText('inventory-event-1')).toBeTruthy()
    expect(within(detail).getByText('State not reported')).toBeTruthy()
    expect(within(detail).getByText('Store')).toBeTruthy()
    expect(within(detail).queryByText('Observation evidence')).toBeNull()
    expect(screen.getByText('Model and risk: unknown. Observation volume does not establish usage or confidence.')).toBeTruthy()
  })
  it.each(['viewer', undefined] as const)('does not fetch or advertise the route for role %s', role => {
    useAuthStore.setState({ user: role ? { ...analyst, role } : null })
    const get = serve(); mount(true)
    expect(screen.getByRole('alert').textContent).toContain('analyst or administrator')
    expect(get).not.toHaveBeenCalled()
    expect(screen.queryByRole('link', { name: 'AI cartography' })).toBeNull()
  })
  it.each([401, 403])('latches %s across remount and allows a new legitimate session to recover', async status => {
    const get = serve(); const initial = get.getMockImplementation()!
    const first = mount(); await screen.findByText(event.event_id)
    get.mockRejectedValue(error(status))
    await act(async () => { await first.queries.invalidateQueries({ queryKey: ['cartography'] }) })
    expect(screen.getByRole('alert').textContent).toContain('Cartography access denied')
    expect(screen.queryByText('192.0.2.1 → Reviewed service')).toBeNull()
    const calls = get.mock.calls.length; first.unmount(); mount()
    await act(async () => {})
    expect(get).toHaveBeenCalledTimes(calls)
    expect(screen.getByRole('alert').textContent).toContain('Cartography access denied')
    get.mockImplementation(initial)
    act(() => useAuthStore.getState().login('new-csrf', analyst))
    expect(await screen.findByText(event.event_id)).toBeTruthy()
  })
  it('rejects late catalog, inventory and network responses after one family denies access', async () => {
    const get = serve()
    const resolves: Array<{ url: string; resolve: (value: { data: unknown }) => void }> = []
    get.mockImplementation(url => url?.startsWith('/network/relations') ? Promise.reject(error(403)) : new Promise(resolve => { resolves.push({ url: url!, resolve }) }))
    const { queries } = mount()
    await screen.findByRole('alert')
    await act(async () => { resolves.forEach(({ url, resolve }) => resolve({ data: url.startsWith('/extensions') ? { items: [{ ...installation, host_label: 'SENSITIVE_LATE_HOST' }], total: 1, identity_window: { days: 30, as_of: stamp } } : [{ ...service, canonical_name: 'SENSITIVE_LATE_SERVICE' }] })) })
    expect(screen.queryByText('Reviewed service')).toBeNull()
    expect(screen.queryByText('SENSITIVE_LATE_HOST')).toBeNull()
    expect(screen.queryByText('SENSITIVE_LATE_SERVICE')).toBeNull()
    expect(screen.queryByRole('complementary', { name: 'Evidence detail' })).toBeNull()
    expect(queries.getQueriesData({ queryKey: ['cartography'] }).every(([, data]) => data === undefined)).toBe(true)
    expect(useAuthStore.getState().cartographyDeniedSession).toBe(useAuthStore.getState().session)
  })
  it('cancels filter/unmount reads and resets live data when demo/session/role changes', async () => {
    const get = serve(); const original = get.getMockImplementation()!; const first = mount(); await screen.findByText(event.event_id)
    get.mockImplementation((url, config) => url?.startsWith('/network/relations') && url.includes('hours=168') ? new Promise(() => {}) : original(url, config))
    fireEvent.change(screen.getByLabelText(/Observation window/), { target: { value: '168' } })
    await waitFor(() => expect(get.mock.calls.some(([url]) => url?.includes('hours=168'))).toBe(true))
    const active = get.mock.calls.filter(([url]) => url?.startsWith('/network/relations')).at(-1)?.[1]?.signal as AbortSignal
    get.mockImplementation(() => new Promise(() => {}))
    act(() => useAuthStore.getState().enterDemo())
    await waitFor(() => expect(active.aborted).toBe(true))
    expect(screen.getByText(/Synthetic network observations/)).toBeTruthy()
    expect(screen.queryByText(event.event_id)).toBeNull()
    act(() => useAuthStore.setState({ user: { ...analyst, role: 'viewer' } }))
    expect(screen.queryByText(event.event_id)).toBeNull()
    first.unmount()
  })
  it.each(['/network/relations', '/extensions/inventory', '/catalog?', '/network/events?', '/catalog/', '/network/events/'])('a403 from %s clears every data family and cancels the scene', async endpoint => {
    const get = serve(); const original = get.getMockImplementation()!
    get.mockImplementation((url, config) => url?.startsWith(endpoint) ? Promise.reject(error(403)) : original(url, config))
    mount()
    if (endpoint === '/network/events/') fireEvent.click(await screen.findByText(event.event_id))
    expect((await screen.findByRole('alert')).textContent).toContain('Cartography access denied')
    expect(screen.queryByRole('complementary', { name: 'Evidence detail' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Simulate context loss' })).toBeNull()
    expect(screen.queryByText('PRIVATE_ERROR_MUST_NOT_RENDER')).toBeNull()
  })
  it('discards a valid late network response after inventory denial and after logout', async () => {
    const get = serve(); const original = get.getMockImplementation()!
    let resolveNetwork: ((value: { data: NetworkRelations }) => void) | undefined
    get.mockImplementation((url, config) => url?.startsWith('/network/relations') ? new Promise(resolve => { resolveNetwork = resolve }) : url?.startsWith('/extensions/inventory') ? Promise.reject(error(403)) : original(url, config))
    mount(); await screen.findByRole('alert')
    act(() => useAuthStore.getState().logout())
    await act(async () => { resolveNetwork?.({ data: { ...relations, items: [{ ...relations.items[0], source_ip: '192.0.2.244' }] } }) })
    expect(screen.queryByText(/192.0.2.244/)).toBeNull()
    expect(useAuthStore.getState().cartographyDeniedSession).toBeNull()
  })
  it('an old-session denial cannot poison a new authenticated session', () => {
    const old = useAuthStore.getState().session
    useAuthStore.getState().login('new', analyst)
    const before = useAuthStore.getState()
    useAuthStore.getState().denyCartography(old)
    expect(useAuthStore.getState()).toBe(before)
    expect(useAuthStore.getState().cartographyDeniedSession).toBeNull()
  })
  it('distinguishes API truncation, local graph caps and full-window counts with complete paginated escape routes', async () => {
    const get = serve(); const original = get.getMockImplementation()!
    const items = Array.from({ length: 500 }, (_, i) => ({ ...relations.items[0], domain: `domain-${i}.test`, observations: 1 }))
    get.mockImplementation((url, config) => url?.startsWith('/network/relations') ? Promise.resolve({ data: { ...relations, items, total_observations: 701, total_relations: 701, represented_observations: 500, represented_relations: 500, truncated: true } }) : original(url, config))
    mount()
    expect(await screen.findByText(/Server returned 500 of 701 network relationships/)).toBeTruthy()
    expect(screen.getByText(/180 loaded relationships omitted from the graph/)).toBeTruthy()
    expect(screen.getByText(/Server relation limit reached/)).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Open network observations' }).getAttribute('href')).toBe('/network?hours=24')
    expect(screen.getByRole('link', { name: 'Open the complete inventory' }).getAttribute('href')).toBe('/extensions?view=inventory')
    fireEvent.click(screen.getByText('Coverage and interpretation'))
    expect(screen.getByText(/Graph shows 320 of 701 network observations/)).toBeTruthy()
  })
})

describe.each(['en', 'fr', 'zh-CN'] as const)('%s authored and raw cartography text', locale => {
  it('uses a real LocaleProvider for known server prose and missing addresses while preserving unknown raw values', async () => {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale)
    const get = serve(); const original = get.getMockImplementation()!
    const anonymous = { ...event, src_ip: null, dst_ip: null, dst_port: null, domain: null, sni: null, url_host: null, matched: false, catalog_match_id: null, match_field: null, match_confidence: null }
    get.mockImplementation((url, config) => url?.startsWith('/network/relations') ? Promise.resolve({ data: { ...relations, limitations: [...relations.limitations, ...relationWarnings], items: [{ ...relations.items[0], source_ip: '', domain: '', catalog_match_id: null }] } }) : url?.startsWith('/network/events/') ? Promise.resolve({ data: anonymous }) : original(url, config))
    mount(); const i18n = createI18n(locale)
    expect(await screen.findByRole('heading', { name: i18n.tr('AI cartography') })).toBeTruthy()
    expect(await screen.findByText(`${i18n.tr('Source address not observed')} → ${i18n.tr('Hostname not observed')}`)).toBeTruthy()
    fireEvent.click(screen.getByText(i18n.tr('Coverage and interpretation')))
    expect(screen.getByText(i18n.tr(relations.limitations[0] as 'Counts cover imported observations only; unobserved traffic and sensor outages are unknown.'))).toBeTruthy()
    for (const warning of relationWarnings) expect(screen.getByText(i18n.tr(warning))).toBeTruthy()
    expect(screen.getByText('__proto__')).toBeTruthy()
    expect(screen.getByText('Raw upstream evidence remains verbatim')).toBeTruthy()
    fireEvent.click(await screen.findByText(event.event_id))
    expect(await screen.findByText(i18n.tr('Stored matching field'))).toBeTruthy()
    expect(screen.getAllByText(i18n.tr('Not observed'))).toHaveLength(4)
  })
  it('translates known installation source/state while leaving unknown reported values untouched', async () => {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale)
    serve([{ ...installation, host_label: '__proto__', extension_name: 'Raw extension name' }]); mount()
    const i18n = createI18n(locale)
    expect(await screen.findByRole('link', { name: i18n.tr('Open discovery evidence') })).toBeTruthy()
    expect(screen.getByText(i18n.tr('Store'))).toBeTruthy()
    expect(screen.getByText(i18n.tr('State not reported'))).toBeTruthy()
    expect(screen.getAllByText('__proto__').length).toBeGreaterThan(0)
    expect(screen.getByText('Raw extension name')).toBeTruthy()
  })
})
