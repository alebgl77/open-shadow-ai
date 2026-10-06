import client from './client'

export interface Detection {
  detection_id: string
  entity_name: string
  entity_type: string
  entity_category: string | null
  catalog_item_id: string | null
  classification: string
  shadow_ai_status: string
  confidence_score: number
  confidence_level: string
  risk_score: number
  risk_level: string
  risk_score_stale?: boolean
  risk_calculated_at?: string | null
  governance_status?: 'none' | 'active' | 'expired'
  first_seen_at: string
  last_seen_at: string
  impacted_users_count: number
  impacted_devices_count: number
  total_events_count: number
  source_types: string[]
  primary_evidence: string | null
  evidence_bundle: Record<string, unknown>
  reasoning_summary: string | null
  analyst_status: string
  analyst_notes: string | null
  reviewed_at: string | null
  recommended_action: string | null
  created_at: string
  updated_at: string
}

export interface DetectionListResponse {
  items: Detection[]
  total: number
  page: number
  page_size: number
}

// Mirrors SORT_COLUMNS in src/shadai/api/detections.py; the API rejects any other value.
export const DETECTION_SORT_COLUMNS = ['last_seen_at', 'first_seen_at', 'risk_score', 'confidence_score', 'entity_name', 'total_events_count', 'impacted_users_count', 'impacted_devices_count'] as const
export type DetectionSortColumn = typeof DETECTION_SORT_COLUMNS[number]

export interface DetectionFilter {
  classification?: string
  risk_level?: string
  confidence_level?: string
  entity_type?: string
  analyst_status?: string
  search?: string
  page?: number
  page_size?: number
  sort_by?: DetectionSortColumn
  sort_order?: string
}

export const listDetections = (filters: DetectionFilter = {}) => {
  const params = new URLSearchParams()
  const normalized = { ...filters, page: Math.max(1, Math.floor(Number(filters.page) || 1)), page_size: Math.max(10, Math.min(100, Math.floor(Number(filters.page_size) || 25))) }
  Object.entries(normalized).forEach(([k, v]) => { if (v) params.set(k, String(v)) })
  return client.get<DetectionListResponse>(`/detections?${params}`).then(r => r.data)
}

export const getDetection = (id: string) =>
  client.get<Detection>(`/detections/${id}`).then(r => r.data)

export const updateDetection = (id: string, body: { classification?: string; analyst_status?: string; analyst_notes?: string }) =>
  client.patch<Detection>(`/detections/${id}`, body).then(r => r.data)

export const getDetectionTimeline = (id: string) =>
  client.get<Array<{ type: string; timestamp: string; description: string }>>(`/detections/${id}/timeline`).then(r => r.data)

export const ANTI_HR_NOTICE = 'Open Shadow AI is an IT governance tool. This data must not be used for individual employee surveillance, disciplinary action, performance evaluation or behavioural profiling.'
const EXPORT_FILTERS = ['classification', 'risk_level', 'confidence_level', 'entity_type', 'analyst_status', 'search', 'sort_by', 'sort_order'] as const

/** Every discovery matching the filters, exported and audited by the server (analyst role). */
export async function exportDetections(filters: DetectionFilter): Promise<{ blob: Blob; filename: string }> {
  const params = new URLSearchParams({ format: 'csv' })
  EXPORT_FILTERS.forEach(key => { const value = filters[key]; if (value) params.set(key, String(value)) })
  const response = await client.post<Blob | string>(`/exports/detections?${params}`, undefined, { responseType: 'blob' })
  const disposition = String(response.headers?.['content-disposition'] ?? '')
  const suggested = /filename="?([^";]+)"?/i.exec(disposition)?.[1] ?? 'open-shadow-ai-discoveries.csv'
  const blob = response.data instanceof Blob ? response.data : new Blob([String(response.data)], { type: 'text/csv;charset=utf-8;' })
  return { blob, filename: suggested.replace(/[^\w.-]/g, '_') }
}
