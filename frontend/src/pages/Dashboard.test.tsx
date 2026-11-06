// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import client from '@/api/client'
import type { DashboardSummary, EvidenceSummary, SourceHealth } from '@/api/dashboard'
import { createI18n, LocaleContext, type Locale } from '@/i18n'
import { useAuthStore } from '@/stores/auth'
import Dashboard from './Dashboard'

const emptyEvidence: EvidenceSummary = {
  window_days: 30,
  window_start: '2026-10-01T13:30:00Z',
  window_end: '2026-10-31T13:30:00Z',
  total_events: 0,
  by_category: [],
  by_source: [],
  models: [],
  measurement: { model_known_events: 0, tokens_reported_events: 0, cost_reported_events: 0, input_tokens: null, output_tokens: null, cost_usd: null },
  unique_users: 0,
  unique_devices: 0,
}
const emptySummary: DashboardSummary = { total: 0, unsanctioned: 0, high_risk: 0, unreviewed: 0 }

function mockDashboard({
  evidence = emptyEvidence,
  sources = [],
  summary = emptySummary,
}: {
  evidence?: EvidenceSummary | Error
  sources?: SourceHealth[] | Error
  summary?: DashboardSummary | Error
} = {}) {
  vi.spyOn(client, 'get').mockImplementation(async url => {
    const response = {
      '/dashboard/evidence?days=30': evidence,
      '/dashboard/source-health': sources,
      '/dashboard/summary': summary,
      '/dashboard/trend?days=30': [],
    }[url] ?? { items: [], total: 0, page: 1, page_size: 10 }
    if (response instanceof Error) throw response
    return { data: response }
  })
}

function openDashboard(locale: Locale = 'en') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<LocaleContext.Provider value={{ ...createI18n(locale), setLocale: () => {} }}>
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route path="/dashboard" element={<Dashboard/>}/>
          <Route path="/sources" element={<p>Source details destination</p>}/>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  </LocaleContext.Provider>)
}

afterEach(() => { cleanup(); useAuthStore.getState().logout(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('dashboard pilot checkpoint', () => {
  it.each([
    ['en', 'Pilot checkpoint', 'No events observed in this window.'],
    ['fr', 'Point d’étape du pilote', 'Aucun événement observé sur cette période.'],
    ['zh-CN', '试点检查', '此窗口内未观测到事件。'],
  ] as const)('renders an empty observation window in %s without a model percentage', async (locale, heading, empty) => {
    mockDashboard()
    openDashboard(locale)
    const checkpoint = within(screen.getByRole('region', { name: heading }))
    expect(await checkpoint.findByText(empty)).toBeTruthy()
    expect(checkpoint.queryByText(/0\s*%/)).toBeNull()
    const time = screen.getByRole('region', { name: heading }).querySelector('time')
    expect(time?.getAttribute('datetime')).toBe(emptyEvidence.window_start)
    expect(time?.textContent).toMatch(/UTC/)
  })

  it('keeps zero model reporting and review counts tied to their separate scopes', async () => {
    mockDashboard({ evidence: { ...emptyEvidence, total_events: 8 }, summary: { ...emptySummary, total: 4, unreviewed: 3 } })
    openDashboard()
    const checkpoint = within(screen.getByRole('region', { name: 'Pilot checkpoint' }))
    expect(await checkpoint.findByText('Model reporting · 0% (0 of 8 events)')).toBeTruthy()
    expect(await checkpoint.findByText('New findings · 3')).toBeTruthy()
    expect(checkpoint.getByText('This count can include retained findings from outside the observation window.')).toBeTruthy()
    expect(await checkpoint.findByText('No source types returned.')).toBeTruthy()
  })

  it('shows an unavailable query separately from a successful empty response', async () => {
    mockDashboard({ evidence: new Error('offline'), sources: new Error('offline') })
    openDashboard()
    const checkpoint = within(screen.getByRole('region', { name: 'Pilot checkpoint' }))
    expect(checkpoint.getByText('Loading evidence…')).toBeTruthy()
    expect(checkpoint.getByText('Checking sources…')).toBeTruthy()
    expect(await checkpoint.findByText('Evidence metrics unavailable')).toBeTruthy()
    expect(await checkpoint.findByText('Source health is unavailable.')).toBeTruthy()
    expect(await checkpoint.findByText('No new findings among retained detections.')).toBeTruthy()
    expect(checkpoint.queryByText('No events observed in this window.')).toBeNull()
    expect(checkpoint.queryByText('No source types returned.')).toBeNull()
  })

  it('shows retained source timestamps and keeps navigation inside the synthetic demo', async () => {
    if (typeof globalThis.ResizeObserver === 'undefined') vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
    const requestedAt = Date.now()
    useAuthStore.getState().enterDemo()
    const session = useAuthStore.getState()
    openDashboard()
    const checkpoint = within(screen.getByRole('region', { name: 'Pilot checkpoint' }))
    fireEvent.click(await checkpoint.findByText('Last event by source'))
    const checked = checkpoint.getByText('Source status checked ·').querySelector('time')
    expect(Date.parse(checked?.dateTime ?? '')).toBeGreaterThanOrEqual(requestedAt)
    expect(checked?.textContent).toMatch(/UTC/)
    const sourceRows = checkpoint.getAllByRole('listitem')
    expect(sourceRows.some(row => /Recent event/.test(row.textContent ?? '') && row.querySelector('time[datetime]'))).toBe(true)
    expect(sourceRows.some(row => /Older event/.test(row.textContent ?? '') && row.querySelector('time[datetime]'))).toBe(true)
    expect(sourceRows.some(row => /No retained event/.test(row.textContent ?? '') && !row.querySelector('time'))).toBe(true)
    expect(checkpoint.getByRole('link', { name: 'Open review queue' }).getAttribute('href')).toBe('/discoveries?analyst_status=new')
    fireEvent.click(checkpoint.getByRole('link', { name: 'Sources & coverage' }))
    expect(await screen.findByText('Source details destination')).toBeTruthy()
    expect(useAuthStore.getState()).toBe(session)
  })
})
