// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosHeaders } from 'axios'
import client from '@/api/client'
import { ANTI_HR_NOTICE, exportDetections, type Detection, type DetectionListResponse } from '@/api/detections'
import { demoRequest, resetDemo } from '@/api/demo'
import { useAuthStore } from '@/stores/auth'
import * as downloads from '@/lib/export'
import DiscoveryList from './DiscoveryList'

const listing: DetectionListResponse = { items: [], total: 7, page: 1, page_size: 25 }
function renderList(role: 'admin' | 'analyst' | 'viewer', path = '/discoveries?risk_level=high&search=chat', response = listing) {
  useAuthStore.getState().login('csrf', { user_id: '1', username: role, email: null, role, is_active: true })
  vi.spyOn(client, 'get').mockResolvedValue({ data: response })
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return { ...render(<QueryClientProvider client={queries}><MemoryRouter initialEntries={[path]}><DiscoveryList /></MemoryRouter></QueryClientProvider>), queries }
}
beforeEach(() => { useAuthStore.getState().logout() })
afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('audited export of every matching discovery', () => {
  it('posts the current filters to the server export and keeps a safe file name', async () => {
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: new Blob(['# WARNING\n']), headers: new AxiosHeaders({ 'content-disposition': 'attachment; filename="../shadai detections.csv"' }) })
    const result = await exportDetections({ risk_level: 'high,critical', search: 'chat', sort_by: 'risk_score', sort_order: 'desc', page: 3, page_size: 25 })
    expect(post).toHaveBeenCalledWith('/exports/detections?format=csv&risk_level=high%2Ccritical&search=chat&sort_by=risk_score&sort_order=desc', undefined, { responseType: 'blob' })
    expect(result.filename).toBe('.._shadai_detections.csv')
    expect(result.blob).toBeInstanceOf(Blob)
  })
  it('is hidden from viewers, who cannot export', async () => {
    renderList('viewer')
    await screen.findByText('7 results')
    expect(screen.queryByRole('button', { name: 'Export all' })).toBeNull()
  })
  it('shows the anti-HR notice before an analyst confirms, then downloads the server file', async () => {
    const createObjectURL = vi.fn(() => 'blob:export')
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: new Blob(['rows']), headers: new AxiosHeaders({ 'content-disposition': 'attachment; filename=shadai_detections_20261002.csv' }) })
    renderList('analyst')
    await screen.findByText('7 results')
    fireEvent.click(screen.getByRole('button', { name: 'Export all' }))
    expect(screen.getByText(/must not be used for individual employee surveillance/).textContent).toContain(ANTI_HR_NOTICE)
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm export' }))
    await waitFor(() => expect(click).toHaveBeenCalledOnce())
    expect(post.mock.calls[0][0]).toBe('/exports/detections?format=csv&risk_level=high&search=chat&sort_by=last_seen_at&sort_order=desc')
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(screen.queryByRole('button', { name: 'Confirm export' })).toBeNull()
  })
  it('exports matching synthetic discoveries in the demo and records the export', () => {
    resetDemo()
    const csv = demoRequest('post', '/exports/detections?format=csv&risk_level=high,critical') as string
    expect(csv.startsWith('# WARNING: Synthetic demo export.')).toBe(true)
    expect(csv.split('\r\n')).toHaveLength(3)
    expect((demoRequest('get', '/audit/logs') as Array<{ action: string }>)[0].action).toBe('export_detections')
  })
})

function detection(id: string): Detection {
  return {
    detection_id: id, entity_name: id, entity_type: 'saas_app', entity_category: null, catalog_item_id: null,
    classification: 'unknown', shadow_ai_status: 'detected', confidence_score: 80, confidence_level: 'high',
    risk_score: 50, risk_level: 'medium', first_seen_at: '2026-09-01T12:00:00Z', last_seen_at: '2026-09-01T12:00:00Z',
    impacted_users_count: 1, impacted_devices_count: 1, total_events_count: 1, source_types: [], primary_evidence: null,
    evidence_bundle: {}, reasoning_summary: null, analyst_status: 'new', analyst_notes: null, reviewed_at: null,
    recommended_action: null, created_at: '2026-09-01T12:00:00Z', updated_at: '2026-09-01T12:00:00Z',
  }
}

describe('matching discovery results', () => {
  it.each(['filter', 'page'])('blocks stale exports and selections during a delayed %s change', async change => {
    const oldResults = { ...listing, items: [detection('Old tool')], total: 30 }
    const newResults = { ...oldResults, items: [detection('New tool')], page: change === 'page' ? 2 : 1 }
    const csv = vi.spyOn(downloads, 'downloadCsv').mockImplementation(() => undefined)
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: new Blob(['new rows']), headers: {} })
    const patch = vi.spyOn(client, 'patch').mockResolvedValue({ data: newResults.items[0] })
    renderList('analyst', '/discoveries', oldResults)
    await screen.findByRole('link', { name: 'Old tool' })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select Old tool' }))
    fireEvent.click(screen.getByRole('button', { name: 'Export all' }))
    expect(screen.getByRole('button', { name: 'Confirm export' })).toBeTruthy()
    let answer: (value: { data: DetectionListResponse }) => void = () => undefined
    vi.mocked(client.get).mockReturnValueOnce(new Promise(resolve => { answer = resolve }))
    if (change === 'filter') {
      fireEvent.click(screen.getByRole('button', { name: 'Filters' }))
      fireEvent.change(screen.getByRole('combobox', { name: 'Risk' }), { target: { value: 'high' } })
    } else fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(screen.getByRole('status').textContent).toBe('Updating results…')
    expect(screen.getByRole('link', { name: 'Old tool' })).toBeTruthy()
    for (const name of ['Export page', 'Export all']) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement
      expect(button.disabled).toBe(true)
      fireEvent.click(button)
    }
    for (const checkbox of screen.getAllByRole('checkbox') as HTMLInputElement[]) {
      expect(checkbox.disabled).toBe(true)
      expect(checkbox.checked).toBe(false)
      fireEvent.click(checkbox)
    }
    expect(screen.queryByRole('button', { name: 'Confirm export' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'sanctioned' })).toBeNull()
    expect(csv).not.toHaveBeenCalled()
    expect(post).not.toHaveBeenCalled()
    expect(patch).not.toHaveBeenCalled()
    vi.mocked(client.get).mockResolvedValue({ data: newResults })
    await act(async () => { answer({ data: newResults }) })
    await screen.findByRole('link', { name: 'New tool' })
    expect(screen.queryByRole('status')).toBeNull()
    for (const name of ['Export page', 'Export all']) expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(false)
    const checkbox = screen.getByRole('checkbox', { name: 'Select New tool' }) as HTMLInputElement
    expect(checkbox.disabled).toBe(false)
    expect(checkbox.checked).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Export page' }))
    expect(csv.mock.calls[0][0][1][0]).toBe('New tool')
    fireEvent.click(checkbox)
    fireEvent.click(screen.getByRole('button', { name: 'sanctioned' }))
    await waitFor(() => expect(patch).toHaveBeenCalledExactlyOnceWith('/detections/New tool', { classification: 'sanctioned' }))
  })

  it('preserves valid selections on refetch and discards IDs removed from fresh results', async () => {
    const response = { ...listing, items: [detection('Kept tool'), detection('Removed tool')] }
    const { queries } = renderList('analyst', '/discoveries', response)
    await screen.findByRole('link', { name: 'Kept tool' })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select visible discoveries' }))
    let answer: (value: { data: DetectionListResponse }) => void = () => undefined
    vi.mocked(client.get).mockReturnValueOnce(new Promise(resolve => { answer = resolve }))
    act(() => { void queries.invalidateQueries() })
    await screen.findByRole('status')
    expect((screen.getByRole('checkbox', { name: 'Select Kept tool' }) as HTMLInputElement).checked).toBe(true)
    await act(async () => { answer({ data: { ...response, items: [response.items[0]] } }) })
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Removed tool' })).toBeNull())
    expect(screen.getByText('1 selected')).toBeTruthy()
    act(() => { queries.setQueryData(['detections', {}], response) })
    await screen.findByRole('link', { name: 'Removed tool' })
    expect((screen.getByRole('checkbox', { name: 'Select Removed tool' }) as HTMLInputElement).checked).toBe(false)
    expect((screen.getByRole('checkbox', { name: 'Select Kept tool' }) as HTMLInputElement).checked).toBe(true)
  })

  it('keeps exports unavailable while loading and when the changed query fails', async () => {
    let answer: (reason: Error) => void = () => undefined
    renderList('analyst')
    expect(screen.getByText('Loading results…')).toBeTruthy()
    for (const name of ['Export page', 'Export all']) expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(true)
    await screen.findByText('7 results')
    vi.mocked(client.get).mockReturnValueOnce(new Promise((_resolve, reject) => { answer = reject }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Search discoveries' }), { target: { value: 'offline' } })
    fireEvent.keyDown(screen.getByRole('textbox', { name: 'Search discoveries' }), { key: 'Enter' })
    await act(async () => { answer(new Error('offline')) })
    expect(await screen.findByText('Failed to load detections')).toBeTruthy()
    for (const name of ['Export page', 'Export all']) expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(true)
  })
})
