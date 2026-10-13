// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosError, AxiosHeaders } from 'axios'
import client from '@/api/client'
import { demoRequest, resetDemo } from '@/api/demo'
import { ANTI_HR_NOTICE } from '@/api/detections'
import { exportExtensionInventory, type ExtensionInventoryItem, type ExtensionInventoryPage, type ExtensionVersionChange, type InstallationHistory, type InventorySummary, type VersionChangePage } from '@/api/inventory'
import { createI18n, LOCALE_STORAGE_KEY, LocaleProvider, type Locale } from '@/i18n'
import * as downloads from '@/lib/export'
import { useAuthStore } from '@/stores/auth'
import Extensions from './Extensions'

const analyst = { user_id: 'inventory-analyst', username: 'analyst', email: null, role: 'analyst' as const, is_active: true }
const KEY = 'a'.repeat(64)
const LEGACY_KEY = 'b'.repeat(64)
const identity_window = { days: 30, as_of: '2026-10-06T12:00:00Z' }
const sider: ExtensionInventoryItem = {
  inventory_key: KEY, host_label: 'host-alpha', user_label: 'p1_alice', browser: 'chrome', profile: 'Default', extension_id: 'sider-extension-id',
  extension_name: 'Sider assistant', version: '1.1.0', enabled: true, install_source: 'store', installed_at: '2026-09-01T08:00:00Z',
  first_seen_at: '2026-09-02T08:00:00Z', last_seen_at: '2026-10-06T10:00:00Z', catalog_item_id: 'opaque-catalog-id', detection_id: 'detection-7',
  collector_id: 'pilot-agent', last_event_id: 'event-1', wire_version: 2, present_in_latest_snapshot: true,
}
const legacy: ExtensionInventoryItem = {
  ...sider, inventory_key: LEGACY_KEY, host_label: 'host-beta', user_label: null, profile: '', extension_id: 'legacy-extension-id', extension_name: 'Legacy helper',
  version: null, enabled: null, install_source: '', installed_at: null, last_seen_at: '2026-10-05T10:00:00Z', catalog_item_id: null, detection_id: null, wire_version: 1, present_in_latest_snapshot: false,
}
const inventory: ExtensionInventoryPage = { items: [sider, legacy], total: 41, page: 1, page_size: 25, identity_window, identity_mode: 'pseudonymized' }
const summary: InventorySummary = {
  installations: 41, hosts: 3, extensions: 9, catalog_matched: 4, by_enabled: { true: 20, false: 11, unknown: 10 }, by_browser: { chrome: 30, firefox: 11 },
  by_install_source: { '': 10, store: 20, user: 3, unpacked: 2, external: 1, policy: 2, component: 1, orphan: 1, unknown: 1 }, version_changes_7d: 5,
  identity_window, identity_mode: 'pseudonymized', limitations: ['Only reported installations are counted.'],
}
const upgrade: ExtensionVersionChange = {
  change_id: 'change-2', inventory_key: KEY, event_id: 'event-2', extension_id: sider.extension_id, extension_name: sider.extension_name, browser: 'chrome', host_label: 'host-alpha',
  user_label: 'p1_alice', profile: 'Default', from_version: '1.0.0', to_version: '1.1.0', previous_observed_at: '2026-10-01T10:00:00Z', observed_at: '2026-10-06T10:00:00Z', catalog_item_id: 'opaque-catalog-id',
}
const first: ExtensionVersionChange = { ...upgrade, change_id: 'change-1', event_id: 'event-1', from_version: null, to_version: '1.0.0', previous_observed_at: '2026-09-02T08:00:00Z', observed_at: '2026-10-01T10:00:00Z' }
const history: InstallationHistory = { installation: sider, changes: [upgrade, first], identity_window, identity_mode: 'pseudonymized' }
const changes: VersionChangePage = { items: [upgrade, first], total: 2, page: 1, page_size: 25, since: '2026-10-03T12:00:00Z', until: '2026-10-06T12:00:00Z', identity_window, identity_mode: 'pseudonymized' }
const detections = { items: [], total: 0, page: 1, page_size: 100 }
const locales: Locale[] = ['en', 'fr', 'zh-CN']
const clients: QueryClient[] = []

function LocationProbe() { const location = useLocation(); return <output aria-label="Current location">{location.pathname}{location.search}</output> }
function Destination() { const location = useLocation(); return <p>Destination {location.pathname}{location.search}</p> }
function mount(path = '/extensions', locale?: Locale) {
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  clients.push(queries)
  if (locale) localStorage.setItem(LOCALE_STORAGE_KEY, locale)
  const tree = <QueryClientProvider client={queries}><MemoryRouter initialEntries={[path]}>
    <Routes><Route path="/extensions" element={<Extensions />} /><Route path="/discoveries" element={<Destination />} /><Route path="/discoveries/:id" element={<Destination />} /></Routes><LocationProbe />
  </MemoryRouter></QueryClientProvider>
  const result = render(locale ? <LocaleProvider>{tree}</LocaleProvider> : tree)
  return { ...result, queries }
}
type Overrides = { inventory?: ExtensionInventoryPage; summary?: InventorySummary; history?: InstallationHistory; changes?: VersionChangePage }
function answer(url: string | undefined, overrides: Overrides = {}) {
  if (url === '/extensions/inventory/summary') return overrides.summary || summary
  if (url?.startsWith('/extensions/inventory/')) return overrides.history || history
  if (url?.startsWith('/extensions/inventory?')) return overrides.inventory || inventory
  if (url?.startsWith('/extensions/version-changes')) return overrides.changes || changes
  if (url?.startsWith('/detections?')) return detections
  throw new Error(`Unexpected request: ${url}`)
}
function serve(overrides: Overrides = {}) { return vi.spyOn(client, 'get').mockImplementation(async url => ({ data: answer(url, overrides) })) }
function forbidden() { return new AxiosError('Forbidden', '403', undefined, undefined, { status: 403, statusText: 'Forbidden', data: {}, headers: {}, config: { headers: new AxiosHeaders() } }) }
const table = () => screen.getByRole('table')
const location = () => screen.getByLabelText('Current location').textContent
beforeEach(() => { localStorage.clear(); resetDemo(); useAuthStore.getState().login('csrf', analyst) })
afterEach(() => { cleanup(); clients.splice(0).forEach(query => query.clear()); useAuthStore.getState().logout(); vi.useRealTimers(); vi.restoreAllMocks() })

describe('extension views', () => {
  it('keeps the catalog-match view as the default, with its paginated-list link and no inventory request', async () => {
    const get = serve()
    mount()
    expect(screen.getByRole('heading', { level: 1, name: 'AI Browser Extensions' })).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Open the complete paginated list' }).getAttribute('href')).toBe('/discoveries?entity_type=browser_extension')
    expect(screen.getByRole('tab', { name: 'Catalog matches' }).getAttribute('aria-selected')).toBe('true')
    expect(await screen.findByText('No AI browser extensions detected')).toBeTruthy()
    expect(get).toHaveBeenCalledWith(expect.stringMatching(/^\/detections\?entity_type=browser_extension/))
    expect(get.mock.calls.some(([url]) => String(url).startsWith('/extensions/'))).toBe(false)
    expect(screen.queryByText(/Identities are pseudonymised/)).toBeNull()
  })

  it('switches views through the view parameter and drops stale parameters', async () => {
    serve()
    mount('/extensions?page=3&enabled=true')
    fireEvent.click(screen.getByRole('tab', { name: 'Inventory' }))
    expect(location()).toBe('/extensions?view=inventory')
    expect(screen.getByRole('tab', { name: 'Inventory' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.queryByRole('link', { name: 'Open the complete paginated list' })).toBeNull()
    expect(await screen.findByText('Sider assistant')).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', { name: 'Version changes' }))
    expect(location()).toBe('/extensions?view=changes')
    expect(await screen.findByText('1.0.0 → 1.1.0')).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', { name: 'Catalog matches' }))
    expect(location()).toBe('/extensions?view=matches')
    expect(screen.getByRole('link', { name: 'Open the complete paginated list' })).toBeTruthy()
  })

  it('falls back to the default view for an unsupported view value', () => {
    serve()
    mount('/extensions?view=bogus')
    expect(screen.getByRole('tab', { name: 'Catalog matches' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.getByRole('link', { name: 'Open the complete paginated list' })).toBeTruthy()
  })
})

describe('extension inventory view', () => {
  it('renders installation rows, state badges, catalog links, absence markers and the identity window', async () => {
    const get = serve()
    mount('/extensions?view=inventory')
    expect(await screen.findByText('Sider assistant')).toBeTruthy()
    const rows = table()
    expect(within(rows).getByText('sider-extension-id')).toBeTruthy()
    expect(within(rows).getByText('host-alpha')).toBeTruthy()
    expect(within(rows).getByText('p1_alice · Default')).toBeTruthy()
    expect(within(rows).getByText('1.1.0')).toBeTruthy()
    expect(within(rows).getByText('Enabled', { selector: 'span' })).toBeTruthy()
    expect(within(rows).getByText('Store')).toBeTruthy()
    expect(within(rows).getByText('Host-level record')).toBeTruthy()
    expect(within(rows).getAllByText('Not reported')).toHaveLength(4)
    expect(within(rows).getByRole('link', { name: 'Open discovery' }).getAttribute('href')).toBe('/discoveries/detection-7')
    expect(within(rows).getByText('No catalog match')).toBeTruthy()
    expect(within(rows).getByText('Absent from the latest snapshot')).toBeTruthy()
    expect(within(rows).getByText(new Date(sider.installed_at!).toLocaleString('en-US'))).toBeTruthy()
    expect(screen.getByText(/An installation is presence evidence, not usage/).textContent).toContain('Identities are pseudonymised.')
    expect(screen.getByText(/Installations reported within the last 30 days/)).toBeTruthy()
    const overview = screen.getByRole('region', { name: 'Inventory overview' })
    expect(within(overview).getByText('Installations').parentElement?.textContent).toBe('Installations41')
    expect(within(overview).getByText('Version changes (7 days)').parentElement?.textContent).toBe('Version changes (7 days)5')
    expect(within(overview).getByText('Unpacked').parentElement?.parentElement?.textContent).toBe('Unpacked2')
    expect(within(overview).getByText('Only reported installations are counted.')).toBeTruthy()
    expect(screen.getByText('41 installations · page 1 of 2')).toBeTruthy()
    expect(screen.queryByText(KEY)).toBeNull()
    expect(get).toHaveBeenCalledWith('/extensions/inventory?page=1&page_size=25&sort_by=last_seen_at&sort_order=desc', expect.objectContaining({ signal: expect.any(AbortSignal) }))
    expect(get).toHaveBeenCalledWith('/extensions/inventory/summary', expect.objectContaining({ signal: expect.any(AbortSignal) }))
    expect(get.mock.calls.some(([url]) => String(url).startsWith('/detections'))).toBe(false)
  })

  it.each(['inventory', 'changes'])('shows an explicit permission state for viewers on the %s view without fetching', view => {
    useAuthStore.getState().login('csrf-viewer', { ...analyst, role: 'viewer' })
    const get = serve()
    mount(`/extensions?view=${view}`)
    expect(screen.getByRole('alert').textContent).toContain('analyst or administrator')
    expect(get).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Export all' })).toBeNull()
    expect(screen.queryByText(/No installations/)).toBeNull()
  })

  it('replaces previously loaded installations with the permission state when the server returns 403', async () => {
    const get = serve()
    const { queries } = mount('/extensions?view=inventory')
    await screen.findByText('Sider assistant')
    get.mockRejectedValue(forbidden())
    await act(async () => { await queries.invalidateQueries() })
    expect((await screen.findByRole('alert')).textContent).toContain('analyst or administrator')
    expect(screen.queryByText('Sider assistant')).toBeNull()
    expect(screen.queryByText('Installations')).toBeNull()
  })

  it('shows live failures without substituting demo or empty data, and retries explicitly', async () => {
    const get = serve()
    get.mockRejectedValue(new Error('offline'))
    mount('/extensions?view=inventory')
    expect(await screen.findByText(/The extension inventory is unavailable. No sample data has been substituted/)).toBeTruthy()
    expect(screen.getByText(/No installation totals can be confirmed/)).toBeTruthy()
    expect(screen.queryByText(/Synthetic extension inventory/)).toBeNull()
    expect(screen.queryByText(/No installations in this selection/)).toBeNull()
    expect(screen.queryByText('Installations')).toBeNull()
    expect(useAuthStore.getState().mode).toBe('live')
    get.mockImplementation(async url => ({ data: answer(url) }))
    for (const button of screen.getAllByRole('button', { name: 'Retry' })) fireEvent.click(button)
    expect(await screen.findByText('Sider assistant')).toBeTruthy()
    expect(screen.getByText('Installations')).toBeTruthy()
  })

  it('resets the page on filter and sort changes and discards old rows while the new page loads', async () => {
    const get = serve({ inventory: { ...inventory, page: 3 } })
    const { queries } = mount('/extensions?view=inventory&page=3')
    await screen.findByText('Sider assistant')
    let resolve: (value: unknown) => void = () => undefined
    get.mockReturnValueOnce(new Promise(answer => { resolve = answer }))
    fireEvent.change(screen.getByRole('combobox', { name: 'Enabled state' }), { target: { value: 'true' } })
    expect(location()).toBe('/extensions?view=inventory&page=1&enabled=true')
    expect(screen.getByText('Loading extension inventory…')).toBeTruthy()
    expect(screen.queryByText('Sider assistant')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Next' })).toBeNull()
    await act(async () => { resolve({ data: { ...inventory, items: [{ ...sider, extension_name: 'Fresh assistant' }] } }) })
    expect(await screen.findByText('Fresh assistant')).toBeTruthy()
    expect(get).toHaveBeenCalledWith('/extensions/inventory?enabled=true&page=1&page_size=25&sort_by=last_seen_at&sort_order=desc', expect.any(Object))
    const key = queries.getQueryCache().getAll().find(query => query.queryKey[0] === 'extension-inventory' && JSON.stringify(query.queryKey).includes('"enabled":"true"'))?.queryKey
    expect(key).toEqual(['extension-inventory', 'live', useAuthStore.getState().session, { enabled: 'true', page: 1, page_size: 25, sort_by: 'last_seen_at', sort_order: 'desc' }])
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(location()).toContain('page=2'))
    expect(screen.queryByRole('button', { name: 'Version' })).toBeNull()
    await screen.findByText('Sider assistant')
    fireEvent.click(screen.getByRole('button', { name: 'Version' }))
    expect(location()).toBe('/extensions?view=inventory&page=1&enabled=true&sort_by=version&sort_order=desc')
    await waitFor(() => expect(get).toHaveBeenCalledWith('/extensions/inventory?enabled=true&page=1&page_size=25&sort_by=version&sort_order=desc', expect.any(Object)))
    fireEvent.click(await screen.findByRole('button', { name: 'Version' }))
    expect(location()).toContain('sort_by=version&sort_order=asc')
    await waitFor(() => expect(get).toHaveBeenCalledWith('/extensions/inventory?enabled=true&page=1&page_size=25&sort_by=version&sort_order=asc', expect.any(Object)))
    await screen.findByText('Sider assistant')
    fireEvent.change(screen.getByRole('textbox', { name: 'Host' }), { target: { value: ' alpha ' } })
    fireEvent.keyDown(screen.getByRole('textbox', { name: 'Host' }), { key: 'Enter' })
    expect(location()).toContain('host=alpha')
    fireEvent.change(screen.getByRole('combobox', { name: 'Browser' }), { target: { value: 'firefox' } })
    await waitFor(() => expect(get).toHaveBeenCalledWith('/extensions/inventory?host=alpha&browser=firefox&enabled=true&page=1&page_size=25&sort_by=version&sort_order=asc', expect.any(Object)))
  })

  it('normalizes unsupported URL filters before issuing requests', async () => {
    const get = serve()
    mount('/extensions?view=inventory&enabled=maybe&install_source=magic,store&catalog_match=all&page=-2&sort_by=evidence&sort_order=sideways&browser=%20')
    await screen.findByText('Sider assistant')
    expect(get).toHaveBeenCalledWith('/extensions/inventory?install_source=store&page=1&page_size=25&sort_by=last_seen_at&sort_order=desc', expect.any(Object))
    expect((screen.getByRole('combobox', { name: 'Enabled state' }) as HTMLSelectElement).value).toBe('')
    expect((screen.getByRole('combobox', { name: 'Install source' }) as HTMLSelectElement).value).toBe('store')
  })

  it('renders empty results without claiming the absence of extensions', async () => {
    serve({ inventory: { ...inventory, items: [], total: 0 } })
    mount('/extensions?view=inventory')
    expect(await screen.findByText('No installations in this selection')).toBeTruthy()
    expect(screen.getByText(/does not establish the absence of extensions/)).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Next' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Export page' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Export all' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('loads the version history of one installation on demand', async () => {
    const get = serve()
    mount('/extensions?view=inventory')
    await screen.findByText('Sider assistant')
    expect(get.mock.calls.some(([url]) => String(url).endsWith('/versions'))).toBe(false)
    const drawer = within(table()).getAllByText('Version history')[0].closest('details')!
    fireEvent.click(within(drawer).getByText('Version history'))
    if (!drawer.open) { drawer.open = true; fireEvent(drawer, new Event('toggle')) }
    expect(await within(drawer).findByText('1.0.0 → 1.1.0')).toBeTruthy()
    expect(within(drawer).getByText('First reported version → 1.0.0')).toBeTruthy()
    expect(get).toHaveBeenCalledWith(`/extensions/inventory/${KEY}/versions`, expect.objectContaining({ signal: expect.any(AbortSignal) }))
    expect(get.mock.calls.filter(([url]) => String(url).endsWith('/versions'))).toHaveLength(1)
  })

  it('exports the visible page locally and every matching installation through the audited server export', async () => {
    const csv = vi.spyOn(downloads, 'downloadCsv').mockImplementation(() => undefined)
    const createObjectURL = vi.fn(() => 'blob:export')
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: new Blob(['rows']), headers: new AxiosHeaders({ 'content-disposition': 'attachment; filename=open-shadow-ai-extension-inventory.csv' }) })
    serve()
    mount('/extensions?view=inventory&browser=chrome&enabled=true&search=sider')
    await screen.findByText('Sider assistant')
    fireEvent.click(screen.getByRole('button', { name: 'Export page' }))
    expect(csv.mock.calls[0][1]).toBe('open-shadow-ai-visible-extension-inventory.csv')
    expect(csv.mock.calls[0][0][1]).toEqual(['host-alpha', 'p1_alice', 'chrome', 'Default', 'Sider assistant', 'sider-extension-id', '1.1.0', 'true', 'store', sider.installed_at, sider.first_seen_at, sider.last_seen_at, true, 'opaque-catalog-id'])
    expect(csv.mock.calls[0][0][2]).toEqual(['host-beta', '', 'chrome', '', 'Legacy helper', 'legacy-extension-id', '', 'unknown', '', '', legacy.first_seen_at, legacy.last_seen_at, false, ''])
    fireEvent.click(screen.getByRole('button', { name: 'Export all' }))
    expect(screen.getByText('Export all 41 matching installations')).toBeTruthy()
    expect(screen.getByText(/must not be used for individual employee surveillance/).textContent).toContain(ANTI_HR_NOTICE)
    expect(screen.getByText(/records this export, with its filters, in the audit log/)).toBeTruthy()
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm export' }))
    await waitFor(() => expect(click).toHaveBeenCalledOnce())
    expect(post).toHaveBeenCalledExactlyOnceWith('/exports/extension-inventory?format=csv&browser=chrome&enabled=true&search=sider&sort_by=last_seen_at&sort_order=desc', undefined, { responseType: 'blob' })
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(screen.queryByRole('button', { name: 'Confirm export' })).toBeNull()
  })

  it('keeps a safe export file name from the server disposition', async () => {
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: 'text rows', headers: new AxiosHeaders({ 'content-disposition': 'attachment; filename="../extension inventory.json"' }) })
    const result = await exportExtensionInventory({ host: 'alpha', install_source: 'store,user', page: 4, page_size: 25, sort_by: 'browser', sort_order: 'asc' })
    expect(post).toHaveBeenCalledWith('/exports/extension-inventory?format=csv&host=alpha&install_source=store%2Cuser&sort_by=browser&sort_order=asc', undefined, { responseType: 'blob' })
    expect(result.filename).toBe('.._extension_inventory.json')
    expect(result.blob).toBeInstanceOf(Blob)
  })

  it('does not let a late live response overwrite a newly entered demo session', async () => {
    let resolve: (value: unknown) => void = () => undefined
    const pending = new Promise(answer => { resolve = answer })
    vi.spyOn(client, 'get').mockImplementation(async url => {
      if (useAuthStore.getState().mode === 'demo') return { data: demoRequest('get', url || '/') }
      return url?.startsWith('/extensions/inventory?') ? pending : { data: answer(url) }
    })
    mount('/extensions?view=inventory')
    await screen.findByText('Loading extension inventory…')
    await act(async () => { useAuthStore.getState().enterDemo() })
    expect(await screen.findAllByText('Sider')).not.toHaveLength(0)
    await act(async () => { resolve({ data: { ...inventory, items: [{ ...sider, extension_name: 'Late live assistant' }] } }) })
    expect(screen.queryByText('Late live assistant')).toBeNull()
    expect(screen.getByText(/Synthetic extension inventory/)).toBeTruthy()
  })

  it('uses the real demo adapter for deterministic inventory counts, filters and history', async () => {
    useAuthStore.getState().enterDemo()
    mount('/extensions?view=inventory')
    expect(await screen.findByText('24 installations · page 1 of 1')).toBeTruthy()
    expect(screen.getByText(/Synthetic extension inventory/).getAttribute('role')).toBe('status')
    expect(within(table()).getAllByRole('link', { name: 'Open discovery' })).toHaveLength(4)
    expect(within(table()).getAllByText('Absent from the latest snapshot')).toHaveLength(2)
    expect(within(table()).getAllByText('Host-level record')).toHaveLength(2)
    fireEvent.change(screen.getByRole('combobox', { name: 'Browser' }), { target: { value: 'chrome' } })
    expect(await screen.findByText('6 installations · page 1 of 1')).toBeTruthy()
    expect(within(table()).queryByText('firefox')).toBeNull()
    fireEvent.change(screen.getByRole('combobox', { name: 'Enabled state' }), { target: { value: 'unknown' } })
    expect(await screen.findByText('2 installations · page 1 of 1')).toBeTruthy()
    const drawer = within(table()).getAllByText('Version history')[0].closest('details')!
    fireEvent.click(within(drawer).getByText('Version history'))
    if (!drawer.open) { drawer.open = true; fireEvent(drawer, new Event('toggle')) }
    expect(await within(drawer).findByText(/→/)).toBeTruthy()
  })
})

describe('version changes view', () => {
  it('requests the selected window, renders the feed and words the notice from the clamped response window', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-10-06T12:00:00Z'))
    const get = serve()
    mount('/extensions?view=changes&hours=72')
    expect(await screen.findByText('1.0.0 → 1.1.0')).toBeTruthy()
    expect(get).toHaveBeenCalledWith('/extensions/version-changes?since=2026-10-03T12%3A00%3A00.000Z&page=1&page_size=25', expect.objectContaining({ signal: expect.any(AbortSignal) }))
    const rows = table()
    expect(within(rows).getByText('First reported version → 1.0.0')).toBeTruthy()
    expect(within(rows).getAllByText('host-alpha · p1_alice · Default')).toHaveLength(2)
    expect(within(rows).getAllByText('Sider assistant')).toHaveLength(2)
    expect(screen.getByText(/2 version changes · page 1 of 1/).textContent).toContain(`Changes observed between ${new Date(changes.since!).toLocaleString('en-US')} and ${new Date(changes.until!).toLocaleString('en-US')}; history is kept for 30 days.`)
    expect(screen.getByText(/A version change is not a security event by itself/)).toBeTruthy()
    expect((screen.getByRole('combobox', { name: 'Change window' }) as HTMLSelectElement).value).toBe('72')
    fireEvent.change(screen.getByRole('combobox', { name: 'Change window' }), { target: { value: '24' } })
    expect(location()).toBe('/extensions?view=changes&hours=24&page=1')
    await waitFor(() => expect(get).toHaveBeenCalledWith('/extensions/version-changes?since=2026-10-05T12%3A00%3A00.000Z&page=1&page_size=25', expect.any(Object)))
    fireEvent.change(screen.getByRole('textbox', { name: 'Extension ID' }), { target: { value: 'sider-extension-id' } })
    fireEvent.keyDown(screen.getByRole('textbox', { name: 'Extension ID' }), { key: 'Enter' })
    await waitFor(() => expect(get).toHaveBeenCalledWith('/extensions/version-changes?since=2026-10-05T12%3A00%3A00.000Z&extension_id=sider-extension-id&page=1&page_size=25', expect.any(Object)))
  })

  it('normalizes an unsupported window and renders empty windows without claiming no update happened', async () => {
    const get = serve({ changes: { ...changes, items: [], total: 0 } })
    mount('/extensions?view=changes&hours=999&page=0')
    expect(await screen.findByText('No version changes in this window')).toBeTruthy()
    expect(screen.getByText(/does not establish that no extension was updated/)).toBeTruthy()
    expect((screen.getByRole('combobox', { name: 'Change window' }) as HTMLSelectElement).value).toBe('24')
    expect(get).toHaveBeenCalledWith(expect.stringMatching(/^\/extensions\/version-changes\?since=.*&page=1&page_size=25$/), expect.any(Object))
  })

  it('shows live failures of the feed without demo data and retries explicitly', async () => {
    const get = serve()
    get.mockImplementation(async url => { if (url?.startsWith('/extensions/version-changes')) throw new Error('offline'); return { data: answer(url) } })
    mount('/extensions?view=changes')
    expect(await screen.findByText(/Version changes are unavailable. No sample data has been substituted/)).toBeTruthy()
    expect(screen.queryByText(/Synthetic extension inventory/)).toBeNull()
    get.mockImplementation(async url => ({ data: answer(url) }))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('1.0.0 → 1.1.0')).toBeTruthy()
  })

  it('uses the real demo adapter for deterministic change windows', async () => {
    useAuthStore.getState().enterDemo()
    mount('/extensions?view=changes')
    expect(await screen.findByText(/3 version changes · page 1 of 1/)).toBeTruthy()
    fireEvent.change(screen.getByRole('combobox', { name: 'Change window' }), { target: { value: '72' } })
    expect(await screen.findByText(/7 version changes · page 1 of 1/)).toBeTruthy()
    fireEvent.change(screen.getByRole('combobox', { name: 'Change window' }), { target: { value: '168' } })
    expect(await screen.findByText(/16 version changes · page 1 of 1/)).toBeTruthy()
    fireEvent.change(screen.getByRole('combobox', { name: 'Browser' }), { target: { value: 'safari' } })
    expect(await screen.findByText(/4 version changes · page 1 of 1/)).toBeTruthy()
    expect(within(table()).queryByText('chrome')).toBeNull()
  })
})

describe.each(locales)('%s inventory labels', locale => {
  const { tr, formatNumber } = createI18n(locale)
  it('localizes the tabs, the filters and the badge labels while keeping evidence verbatim', async () => {
    serve()
    mount('/extensions?view=inventory', locale)
    expect(await screen.findByText('Sider assistant')).toBeTruthy()
    expect(screen.getByRole('tab', { name: tr('Inventory') }).getAttribute('aria-selected')).toBe('true')
    expect(screen.getByRole('tab', { name: tr('Version changes') })).toBeTruthy()
    expect(screen.getByRole('combobox', { name: tr('Enabled state') })).toBeTruthy()
    const rows = table()
    expect(within(rows).getByText(tr('Enabled'), { selector: 'span' })).toBeTruthy()
    expect(within(rows).getByText(tr('Store'))).toBeTruthy()
    expect(within(rows).getByText(tr('Host-level record'))).toBeTruthy()
    expect(within(rows).getAllByText(tr('Not reported'))).toHaveLength(4)
    expect(within(rows).getByText(tr('Absent from the latest snapshot'))).toBeTruthy()
    expect(within(rows).getByText('p1_alice · Default')).toBeTruthy()
    expect(screen.getByText(/p1_alice/)).toBeTruthy()
    expect(screen.getByText(tr('{count} installations · page {page} of {pages}', { count: formatNumber(41), page: formatNumber(1), pages: formatNumber(2) }))).toBeTruthy()
  })
})
