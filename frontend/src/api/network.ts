import client from './client'

export const NETWORK_PROTOCOLS = ['DNS', 'TLS', 'QUIC', 'HTTP'] as const
export type NetworkProtocol = typeof NETWORK_PROTOCOLS[number]
export const NETWORK_NOTICE = 'A lookup or connection is not proof of AI use. A catalog match associates an observed hostname with a service; it does not identify a model, prompts, tokens or a person.'

export interface NetworkOverview {
  hours: number
  total_observations: number
  named_observations: number
  matched_observations: number
  unmatched_observations: number
  protocols: Record<NetworkProtocol, number>
  sensors: { collector_id: string; last_seen: string | null; observations: number }[]
  limitations: string[]
}

export interface NetworkEvent {
  event_id: string
  timestamp: string
  protocol: NetworkProtocol
  domain: string | null
  sni: string | null
  url_host: string | null
  src_ip: string | null
  dst_ip: string | null
  dst_port: number | null
  collector_id: string
  parser_version: string | null
  matched: boolean
  catalog_match_id: string | null
  match_field?: string | null
  match_confidence?: number | null
}

export interface NetworkEvents {
  items: NetworkEvent[]
  total: number
  page: number
  page_size: number
}

export interface NetworkRelation {
  source_ip: string
  domain: string
  catalog_match_id: string | null
  protocol: NetworkProtocol
  observations: number
  first_seen: string
  last_seen: string
}
export interface NetworkRelations {
  hours: number
  protocol: NetworkProtocol | null
  items: NetworkRelation[]
  total_observations: number
  total_relations: number
  represented_observations: number
  represented_relations: number
  truncated: boolean
  limitations: string[]
}
export const getNetworkRelations = (hours: number, protocol?: NetworkProtocol, signal?: AbortSignal) => {
  const params = new URLSearchParams({ hours: String(hours), limit: '500' })
  if (protocol) params.set('protocol', protocol)
  return client.get<NetworkRelations>(`/network/relations?${params}`, { signal }).then(response => response.data)
}
export const getNetworkEvent = (id: string, hours: number, signal?: AbortSignal) =>
  client.get<NetworkEvent>(`/network/events/${encodeURIComponent(id)}?hours=${hours}`, { signal }).then(response => response.data)

export interface NetworkFilters {
  hours: number
  protocol?: NetworkProtocol
  page: number
  page_size: number
  source_ip?: string
  catalog_match_id?: string
  domain?: string
}

export const getNetworkOverview = (hours: number, signal?: AbortSignal) =>
  client.get<NetworkOverview>(`/network/overview?hours=${hours}`, { signal }).then(response => response.data)

export function getNetworkEvents(filters: NetworkFilters, signal?: AbortSignal) {
  const params = new URLSearchParams({ hours: String(filters.hours), page: String(filters.page), page_size: String(filters.page_size) })
  if (filters.protocol) params.set('protocol', filters.protocol)
  // Empty selects an unknown address / an unmatched catalog association; omitted selects all.
  for (const key of ['source_ip', 'catalog_match_id', 'domain'] as const) {
    if (filters[key] !== undefined) params.set(key, filters[key])
  }
  return client.get<NetworkEvents>(`/network/events?${params}`, { signal }).then(response => response.data)
}

export function networkEndpoint(address: string | null, port?: number | null, unavailable = 'Not observed') {
  if (!address) return unavailable
  if (port == null) return address
  return `${address.includes(':') ? `[${address}]` : address}:${port}`
}
