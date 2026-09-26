import client from './client'

export interface DashboardSummary {
  total: number
  unsanctioned: number
  high_risk: number
  unreviewed: number
}

export interface TrendData {
  date: string
  count: number
}

export interface TopTool {
  name: string
  entity_type: string
  classification: string
  events_count: number
  users_count: number
  risk_score: number
}

export interface SourceHealth {
  source_type: string
  status: 'active' | 'warning' | 'inactive'
  last_event: string | null
  events_per_minute: number
}

export const getSummary = () => client.get<DashboardSummary>('/dashboard/summary').then(r => r.data)
export const getTrend = (days = 30) => client.get<TrendData[]>(`/dashboard/trend?days=${days}`).then(r => r.data)
export const getTopTools = (limit = 10) => client.get<TopTool[]>(`/dashboard/top-tools?limit=${limit}`).then(r => r.data)
export const getSourceHealth = () => client.get<SourceHealth[]>('/dashboard/source-health').then(r => r.data)

export interface EvidenceSummary {
  window_days: number
  window_start: string
  window_end: string
  total_events: number
  by_category: { category: string; events: number }[]
  by_source: { source_type: string; evidence_type: string; events: number }[]
  models: { provider: string; model: string; model_provenance: string; events: number }[]
  measurement: { model_known_events: number; tokens_reported_events: number; cost_reported_events: number; input_tokens: number | null; output_tokens: number | null; cost_usd: number | null }
  unique_users: number
  unique_devices: number
}
export const getEvidence = () => client.get<EvidenceSummary>('/dashboard/evidence?days=30').then(r => r.data)
