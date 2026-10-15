import client from '@/api/client'
import { getExtensionInventory, type ExtensionInventoryItem } from '@/api/inventory'
import { getNetworkRelations, type NetworkProtocol } from '@/api/network'
import type { CatalogItem } from '@/types'

export async function loadCatalog(signal: AbortSignal) {
  const result = new Map<string, CatalogItem>()
  let capped = false
  for (let page = 1; page <= 5; page++) {
    const { data } = await client.get<CatalogItem[]>(`/catalog?page=${page}&page_size=100`, { signal })
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
    const before = result.size
    data.forEach(item => result.set(item.catalog_item_id, item))
    if (data.length < 100 || result.size === before) break
    if (page === 5) capped = true
  }
  return { items: [...result.values()], capped }
}
export async function loadInventory(signal: AbortSignal) {
  const result = new Map<string, ExtensionInventoryItem>()
  let total = 0, identity: { days: number; as_of: string } | undefined
  for (let page = 1; page <= 3; page++) {
    const data = await getExtensionInventory({ page, page_size: 100, sort_by: 'last_seen_at', sort_order: 'desc' }, signal)
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
    total = data.total; identity = data.identity_window
    data.items.forEach(item => result.set(item.inventory_key, item))
    if (page * 100 >= total || data.items.length < 100) break
  }
  return { items: [...result.values()], total, truncated: result.size < total, identity }
}
export const loadRelations = (hours: number, protocol: NetworkProtocol | undefined, signal: AbortSignal) => getNetworkRelations(hours, protocol, signal)
export const loadCatalogItem = (id: string, signal: AbortSignal) => client.get<CatalogItem>(`/catalog/${encodeURIComponent(id)}`, { signal }).then(response => response.data)
