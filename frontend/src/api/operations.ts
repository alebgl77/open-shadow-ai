import client from './client'

export const COLLECTOR_SOURCES = ['dns', 'proxy', 'endpoint', 'browser', 'oauth', 'directory', 'instrumented', 'casb', 'network'] as const
export interface CollectorHealth {
  collector_id: string
  display_name: string
  allowed_source_types: string[]
  status: 'revoked' | 'unknown' | 'stale' | 'quiet' | 'active'
  last_server_contact_at: string | null
  last_heartbeat_at: string | null
  last_observed_at: string | null
  server_contact_fresh: boolean
  client_reported: { provenance: 'client_reported'; as_of: string | null; fresh: boolean; queue_events: number | null; queued_bytes: number | null; dropped_events: number | null; expired_events: number | null; rejected_events: number | null; last_success_at: string | null }
  capture_loss: null
}
export interface CollectorPage { items: CollectorHealth[]; total: number; offset: number; limit: number; as_of: string }
export interface CollectorRegistration { collector_id: string; display_name: string; allowed_source_types: string[]; is_active: boolean; revoked_at: string | null }
export interface RegistryPage { items: CollectorRegistration[]; total: number; offset: number; limit: number }
export interface PipelineStream {
  stream: string; status: string; group_present: boolean; retained_entries: number | null; pending: number | null; undelivered: number | null
  oldest_pending_age_seconds: number | null; worker_state_fresh: boolean; last_worker_seen_at: string | null; last_poll_at: string | null; last_progress_at: string | null; last_failure_at: string | null; counters_since: string | null; counters: Record<string, number | null>
}
export interface PipelineHealth { scope: 'deployment'; as_of: string; backend_available: boolean; capture_loss: null; stages: { stage: string; group: string; status: string; deadletter_retained: number; streams: PipelineStream[] }[] }
export interface OnceCredential { api_key: string; expires_at: string; previous_valid_until?: string }
export const getCollectorHealth = (offset: number, signal?: AbortSignal) => client.get<CollectorPage>(`/operations/collectors?offset=${offset}&limit=50`, { signal }).then(r => r.data)
export const getCollectorRegistry = (offset: number, signal?: AbortSignal) => client.get<RegistryPage>(`/collectors?offset=${offset}&limit=50`, { signal }).then(r => r.data)
export const getPipelineHealth = (signal?: AbortSignal) => client.get<PipelineHealth>('/operations/pipeline', { signal }).then(r => r.data)
// Credential responses are awaited directly by local component state. Never use
// a query/mutation cache, persisted store, URL, or logger for these responses.
export const enrollCollector = (body: { collector_id: string; display_name: string; allowed_source_types: string[]; expires_in_days: number }) => client.post<OnceCredential>('/collectors', body).then(r => r.data)
export const rotateCollector = (id: string, body: { overlap_seconds: number; expires_in_days: number }) => client.post<OnceCredential>(`/collectors/${encodeURIComponent(id)}/rotate`, body).then(r => r.data)
export const revokeCollector = (id: string) => client.post(`/collectors/${encodeURIComponent(id)}/revoke`).then(() => undefined)
