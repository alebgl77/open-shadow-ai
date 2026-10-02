// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosHeaders } from 'axios'
import client from '@/api/client'
import { ANTI_HR_NOTICE, exportDetections } from '@/api/detections'
import { demoRequest, resetDemo } from '@/api/demo'
import { useAuthStore } from '@/stores/auth'
import DiscoveryList from './DiscoveryList'

const listing = { items: [], total: 7, page: 1, page_size: 25 }
function renderList(role: 'admin' | 'analyst' | 'viewer', path = '/discoveries?risk_level=high&search=chat') {
  useAuthStore.getState().login('csrf', { user_id: '1', username: role, email: null, role, is_active: true })
  vi.spyOn(client, 'get').mockResolvedValue({ data: listing })
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={queries}><MemoryRouter initialEntries={[path]}><DiscoveryList /></MemoryRouter></QueryClientProvider>)
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
