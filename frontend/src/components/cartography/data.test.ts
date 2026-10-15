import { afterEach, describe, expect, it, vi } from 'vitest'
import client from '@/api/client'
import { loadCatalog, loadInventory } from './data'

afterEach(() => vi.restoreAllMocks())
describe('bounded graph label and inventory reads', () => {
  it('uses five catalog pages of100 at most and labels the cap honestly', async () => {
    const get = vi.spyOn(client, 'get').mockImplementation(async url => {
      const page = Number(new URL(url!, 'https://test.invalid').searchParams.get('page'))
      return { data: Array.from({ length: 100 }, (_, i) => ({ catalog_item_id: `${page}:${i}`, canonical_name: `Item ${page}:${i}` })) }
    })
    const signal = new AbortController().signal
    const result = await loadCatalog(signal)
    expect(result.items).toHaveLength(500); expect(result.capped).toBe(true)
    expect(get).toHaveBeenCalledTimes(5)
    expect(get.mock.calls.every(([url, config]) => url?.endsWith('page_size=100') && config?.signal === signal)).toBe(true)
  })
  it('deduplicates overlapping inventory pages and reports represented vs full totals', async () => {
    const get = vi.spyOn(client, 'get').mockImplementation(async url => {
      const page = Number(new URL(url!, 'https://test.invalid').searchParams.get('page'))
      return { data: { total: 400, items: Array.from({ length: 100 }, (_, i) => ({ inventory_key: `${page === 2 ? 1 : page}:${i}` })), identity_window: { days: 30, as_of: '2026-10-15T00:00:00Z' } } }
    })
    const result = await loadInventory(new AbortController().signal)
    expect(result.items).toHaveLength(200); expect(result.total).toBe(400); expect(result.truncated).toBe(true)
    expect(get).toHaveBeenCalledTimes(3)
    expect(get.mock.calls.every(([url]) => new URL(url!, 'https://test.invalid').searchParams.get('page_size') === '100')).toBe(true)
  })
  it('stops on cancellation even when a transport resolves late rather than honoring AbortSignal', async () => {
    const controller = new AbortController()
    const get = vi.spyOn(client, 'get').mockImplementation(async () => { controller.abort(); return { data: Array.from({ length: 100 }, (_, i) => ({ catalog_item_id: String(i) })) } })
    await expect(loadCatalog(controller.signal)).rejects.toThrow('Aborted')
    expect(get).toHaveBeenCalledTimes(1)
  })
})
