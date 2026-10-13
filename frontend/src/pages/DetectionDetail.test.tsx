// @vitest-environment jsdom
import { cleanup, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import client from '@/api/client'
import { demoRequest, resetDemo } from '@/api/demo'
import type { Detection, TimelineEntry } from '@/api/detections'
import { createI18n, LOCALE_STORAGE_KEY, LocaleProvider, type Locale } from '@/i18n'
import { useAuthStore } from '@/stores/auth'
import DetectionDetail from './DetectionDetail'

const analyst = { user_id: 'detection-analyst', username: 'analyst', email: null, role: 'analyst' as const, is_active: true }
const browser = {
  first_seen: '2026-10-01T10:00:00Z', last_seen: '2026-10-06T10:00:00Z', event_count: 48, confidence_base: .95, matched_field: 'extension_id',
  sample_values: ['sider-extension-id'], sample_observations: [{ field: 'extension_id', value: 'sider-extension-id', observed_at: '2026-10-06T10:00:00Z' }],
  version_changes: [
    { from_version: null, to_version: '1.0.0', observed_at: '2026-10-02T09:00:00Z' },
    { from_version: '1.0.0', to_version: '1.1.0', observed_at: '2026-10-05T09:00:00Z' },
    { from_version: 1, to_version: 'malformed', observed_at: '2026-10-05T10:00:00Z' },
  ],
  versions: { '1.0.0': 2, '1.1.0': 5, '': 1, nested: { host_label: 'host-alpha' }, zero: 0 },
}
const timeline: TimelineEntry[] = [
  { type: 'first_seen', timestamp: '2026-10-01T10:00:00Z', description: 'First detected' },
  { type: 'extension_version_change', timestamp: '2026-10-05T09:00:00Z', description: 'chrome extension updated 1.0.0 -> 1.1.0', browser: 'chrome', from_version: '1.0.0', to_version: '1.1.0' },
  { type: 'extension_version_change', timestamp: '2026-10-05T10:00:00Z', description: 'edge extension updated not reported -> not reported', browser: 'edge', from_version: null, to_version: null },
  { type: 'last_seen', timestamp: '2026-10-06T10:00:00Z', description: 'Last activity' },
]
const clients: QueryClient[] = []

function mount(path: string, locale?: Locale) {
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  clients.push(queries)
  if (locale) localStorage.setItem(LOCALE_STORAGE_KEY, locale)
  const tree = <QueryClientProvider client={queries}><MemoryRouter initialEntries={[path]}>
    <Routes><Route path="/discoveries/:id" element={<DetectionDetail />} /></Routes>
  </MemoryRouter></QueryClientProvider>
  return render(locale ? <LocaleProvider>{tree}</LocaleProvider> : tree)
}
function serve(evidence: Record<string, unknown> = browser, entries: TimelineEntry[] = timeline) {
  const detection = { ...(demoRequest('get', '/detections/demo-6') as Detection), evidence_bundle: { browser: evidence } }
  return vi.spyOn(client, 'get').mockImplementation(async url => ({ data: url?.endsWith('/timeline') ? entries : detection }))
}
beforeEach(() => { localStorage.clear(); resetDemo(); useAuthStore.getState().login('csrf', analyst) })
afterEach(() => { cleanup(); clients.splice(0).forEach(query => query.clear()); useAuthStore.getState().logout(); vi.restoreAllMocks() })

describe('extension version evidence on a detection', () => {
  it('lists hosts per version and the newest changes, and links analysts to the changes view', async () => {
    serve()
    mount('/discoveries/demo-6')
    const region = await screen.findByRole('region', { name: 'Extension versions' })
    expect(within(region).getByText('Hosts by last reported version within the identity window. A version update adds no detection confidence.')).toBeTruthy()
    const rows = within(within(region).getByRole('table')).getAllByRole('row').map(row => row.textContent)
    expect(rows).toEqual(['VersionHosts', '1.1.05', '1.0.02', 'Not reported1'])
    const changes = within(region).getAllByRole('listitem').map(item => item.firstChild?.textContent)
    expect(changes).toEqual(['1.0.0 → 1.1.0', 'First reported version → 1.0.0'])
    expect(within(region).queryByText(/malformed|host-alpha/)).toBeNull()
    expect(within(region).getByRole('link', { name: 'Inspect version changes' }).getAttribute('href')).toBe('/extensions?view=changes&extension_id=sider-extension-id')
  })

  it('colours and words version changes in the timeline from their structured fields', async () => {
    serve()
    mount('/discoveries/demo-6')
    const entry = await screen.findByText('chrome extension updated: 1.0.0 → 1.1.0')
    expect(screen.getByText('edge extension updated: First reported version → Not reported')).toBeTruthy()
    expect(entry.parentElement?.previousElementSibling?.className).toContain('bg-amber-400')
    expect(screen.getByText('First detected').parentElement?.previousElementSibling?.className).toContain('bg-emerald-500')
    expect(screen.queryByText('chrome extension updated 1.0.0 -> 1.1.0')).toBeNull()
  })

  it('keeps identity-free version evidence for viewers without the analyst-only link', async () => {
    useAuthStore.getState().login('csrf-viewer', { ...analyst, role: 'viewer' })
    serve()
    mount('/discoveries/demo-6')
    const region = await screen.findByRole('region', { name: 'Extension versions' })
    expect(within(region).getAllByRole('listitem')).toHaveLength(2)
    expect(within(region).queryByRole('link')).toBeNull()
  })

  it('states when nothing is retained and omits the section for bundles that predate it', async () => {
    serve({ ...browser, version_changes: [], versions: {}, sample_values: [], sample_observations: [] }, [])
    mount('/discoveries/demo-6')
    const region = await screen.findByRole('region', { name: 'Extension versions' })
    expect(within(region).getByText('No reported version is retained.')).toBeTruthy()
    expect(within(region).getByText('No version change observed within the identity window.')).toBeTruthy()
    expect(within(region).getByRole('link', { name: 'Inspect version changes' }).getAttribute('href')).toBe('/extensions?view=changes')
    cleanup()
    vi.restoreAllMocks()
    const { version_changes: _changes, versions: _versions, ...legacy } = browser
    serve(legacy, [])
    mount('/discoveries/demo-6')
    expect(await screen.findByText('sider-extension-id')).toBeTruthy()
    expect(screen.queryByRole('region', { name: 'Extension versions' })).toBeNull()
  })

  it.each(['fr', 'zh-CN'] as const)('localizes version evidence and timeline wording in %s', async locale => {
    serve()
    mount('/discoveries/demo-6', locale)
    const { tr } = createI18n(locale)
    expect(await screen.findByRole('region', { name: tr('Extension versions') })).toBeTruthy()
    expect(screen.getByText(tr('{browser} extension updated: {from} → {to}', { browser: 'chrome', from: '1.0.0', to: '1.1.0' }))).toBeTruthy()
    expect(screen.getByRole('link', { name: tr('Inspect version changes') })).toBeTruthy()
  })

  it('serves demo version evidence and timeline entries for the catalog-matched extension only', () => {
    const sider = demoRequest('get', '/detections/demo-6') as Detection
    const evidence = sider.evidence_bundle.browser as Record<string, unknown>
    expect(evidence.versions).toEqual({ '1.0.0': 1, '': 1, '1.2.0': 1, '1.3.0': 1 })
    expect((evidence.version_changes as Array<{ to_version: string }>).map(change => change.to_version)).toEqual(['1.3.0', '1.2.0', '1.0.0'])
    expect(JSON.stringify(evidence)).not.toMatch(/demo-host|p1_/)
    const entries = demoRequest('get', '/detections/demo-6/timeline') as TimelineEntry[]
    expect(entries.filter(entry => entry.type === 'extension_version_change').map(entry => entry.description)).toEqual([
      'firefox extension updated not reported -> 1.3.0', 'chrome extension updated not reported -> 1.2.0', 'chrome extension updated not reported -> 1.0.0',
    ])
    expect(entries.map(entry => entry.timestamp)).toEqual(entries.map(entry => entry.timestamp).sort())
    const chatgpt = demoRequest('get', '/detections/demo-1') as Detection
    expect(Object.keys(chatgpt.evidence_bundle)).not.toContain('browser')
    expect((demoRequest('get', '/detections/demo-1/timeline') as TimelineEntry[]).map(entry => entry.type)).toEqual(['first_seen', 'last_seen'])
  })
})
