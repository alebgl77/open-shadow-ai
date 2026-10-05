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
}

export interface NetworkEvents {
  items: NetworkEvent[]
  total: number
  page: number
  page_size: number
}

export interface NetworkFilters {
  hours: number
  protocol?: NetworkProtocol
  page: number
  page_size: number
}

export const getNetworkOverview = (hours: number, signal?: AbortSignal) =>
  client.get<NetworkOverview>(`/network/overview?hours=${hours}`, { signal }).then(response => response.data)

export function getNetworkEvents(filters: NetworkFilters, signal?: AbortSignal) {
  const params = new URLSearchParams({ hours: String(filters.hours), page: String(filters.page), page_size: String(filters.page_size) })
  if (filters.protocol) params.set('protocol', filters.protocol)
  return client.get<NetworkEvents>(`/network/events?${params}`, { signal }).then(response => response.data)
}

export function networkEndpoint(address: string | null, port?: number | null) {
  if (!address) return 'Not observed'
  if (port == null) return address
  return `${address.includes(':') ? `[${address}]` : address}:${port}`
}
