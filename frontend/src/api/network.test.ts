import { afterEach, describe, expect, it, vi } from 'vitest'
import client from './client'
import { getNetworkEvent, getNetworkEvents, getNetworkRelations, networkEndpoint, type NetworkEvents, type NetworkRelations } from './network'
import { demoRequest } from './demo'

afterEach(() => vi.restoreAllMocks())
describe('network relation provenance API', () => {
  it('preserves empty exact filters and forwards cancellation on every endpoint', async () => {
    const get = vi.spyOn(client, 'get').mockResolvedValue({ data: {} })
    const controller = new AbortController()
    await getNetworkEvents({ hours: 24, page: 2, page_size: 20, protocol: 'QUIC', source_ip: '', domain: '', catalog_match_id: '' }, controller.signal)
    await getNetworkRelations(168, 'DNS', controller.signal)
    await getNetworkEvent('opaque/id', 24, controller.signal)
    expect(get.mock.calls.map(([url]) => url)).toEqual(['/network/events?hours=24&page=2&page_size=20&protocol=QUIC&source_ip=&catalog_match_id=&domain=', '/network/relations?hours=168&limit=500&protocol=DNS', '/network/events/opaque%2Fid?hours=24'])
    for (const [, config] of get.mock.calls) expect(config?.signal).toBe(controller.signal)
  })
  it('translates only a missing endpoint label and preserves raw addresses / IPv6 formatting', () => {
    expect(networkEndpoint(null, null, 'Non observé')).toBe('Non observé')
    expect(networkEndpoint('2001:db8::1', 443, 'Non observé')).toBe('[2001:db8::1]:443')
    expect(networkEndpoint('toString', undefined, 'Non observé')).toBe('toString')
  })
  it('demo totals genuinely reflect all existing 28/36 records before limiting relationships', () => {
    const a = demoRequest('get', '/network/relations?hours=24&limit=1') as NetworkRelations
    const full = demoRequest('get', '/network/relations?hours=168&limit=500') as NetworkRelations
    expect(a.total_observations).toBe(28)
    expect(a.truncated).toBe(true)
    expect(a.represented_relations).toBe(1)
    expect(a.represented_observations).toBe(a.items[0].observations)
    expect(full.total_observations).toBe(36)
    expect(full.items.reduce((sum, row) => sum + row.observations, 0)).toBe(36)
    const one = full.items[0]
    const params = new URLSearchParams({ hours: '168', source_ip: one.source_ip, catalog_match_id: one.catalog_match_id || '', domain: one.domain, protocol: one.protocol })
    const events = demoRequest('get', `/network/events?${params}`) as NetworkEvents
    expect(events.total).toBe(one.observations)
    expect(events.items.every(event => event.src_ip === one.source_ip && (event.domain || '') === one.domain && event.catalog_match_id === one.catalog_match_id && event.protocol === one.protocol)).toBe(true)
    expect(demoRequest('get', `/network/events/${events.items[0].event_id}?hours=168`)).toEqual(events.items[0])
  })
  it('demo detail rejects unknown/expired IDs and unknown filters select unknown values only', () => {
    expect(() => demoRequest('get', '/network/events/missing?hours=24')).toThrow('Network event not found')
    expect(() => demoRequest('get', '/network/events/demo-network-36?hours=24')).toThrow('Network event not found')
    const unknown = demoRequest('get', '/network/events?hours=24&domain=&catalog_match_id=') as NetworkEvents
    expect(unknown.total).toBe(4)
    expect(unknown.items.every(row => !row.domain && row.catalog_match_id === null)).toBe(true)
    expect((demoRequest('get', '/network/events?hours=24&source_ip=') as NetworkEvents).total).toBe(0)
  })
})
