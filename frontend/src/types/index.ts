// ── Enums ────────────────────────────────────────────────────────
export type RiskLevel = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type ConfidenceLevel = 'low' | 'medium' | 'high' | 'very_high'
export type Classification = 'sanctioned' | 'tolerated' | 'unsanctioned' | 'unknown'
export type AnalystStatus = 'new' | 'investigating' | 'classified' | 'false_positive' | 'escalated'
export type EntityType = 'saas_app' | 'api_service' | 'browser_extension' | 'oauth_app' | 'local_runtime' | 'local_container' | 'desktop_app'

// ── Detection ────────────────────────────────────────────────────
export interface Detection {
  detection_id: string
  entity_name: string
  entity_type: EntityType
  entity_category: string | null
  catalog_item_id: string | null
  classification: Classification
  shadow_ai_status: string
  confidence_score: number
  confidence_level: ConfidenceLevel
  risk_score: number
  risk_level: RiskLevel
  risk_score_stale?: boolean
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
  analyst_status: AnalystStatus
  analyst_id: string | null
  analyst_notes: string | null
  reviewed_at: string | null
  recommended_action: string | null
  governance_id: string | null
  created_at: string
  updated_at: string
}

// ── Governance ───────────────────────────────────────────────────
export interface Governance {
  governance_id: string
  target_type: string
  target_id: string
  org_classification: Classification
  owner: string | null
  exception_policy: string | null
  enforcement_mode: string
  justification: string | null
  approved_by: string | null
  approved_at: string | null
  approved_until: string | null
  approval_status?: 'active' | 'expired'
  created_by: string
  created_at: string
  updated_at: string
}

// ── Catalog ──────────────────────────────────────────────────────
export interface CatalogItem {
  catalog_item_id: string
  canonical_name: string
  aliases: string[]
  category: string
  vendor: string | null
  description: string | null
  domains: string[]
  url_patterns: string[]
  processes: string[]
  extension_ids: string[]
  oauth_app_ids: string[]
  local_ports: number[]
  local_paths: string[]
  container_patterns: string[]
  user_agent_patterns: string[]
  rule_tags: string[]
  default_trust_level: string
  status: string
  source_of_truth: string
  local_override: boolean
  created_at: string
  updated_at: string
}

// ── User views ───────────────────────────────────────────────────
export interface AIUser {
  username: string
  email?: string
  detection_count: number
  highest_risk: RiskLevel
  last_activity: string
  source_types: string[]
}

// ── Audit ────────────────────────────────────────────────────────
export interface AuditEntry {
  audit_id: string
  timestamp: string
  user_id: string
  username: string
  action: string
  resource_type: string | null
  resource_id: string | null
  details: Record<string, unknown>
  ip_address: string | null
}
