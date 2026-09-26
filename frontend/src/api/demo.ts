import { AxiosError, AxiosHeaders, type AxiosAdapter } from 'axios'
import type { Detection } from './detections'
import type { Governance, CatalogItem } from '@/types'

const NOW = Date.now()
const ago = (hours: number) => new Date(NOW - hours * 3600000).toISOString()
const seeds = [
  ['ChatGPT', 'saas_app', 'unsanctioned', 78, 0.94, 12, 486, 'proxy', 'chatgpt.com'],
  ['Claude', 'saas_app', 'tolerated', 43, 0.91, 8, 312, 'proxy', 'claude.ai'],
  ['Microsoft Copilot', 'saas_app', 'sanctioned', 18, 0.98, 24, 624, 'dns', 'copilot.microsoft.com'],
  ['Otter.ai', 'oauth_app', 'unsanctioned', 89, 0.96, 3, 42, 'oauth', 'Calendars.Read'],
  ['Ollama', 'local_runtime', 'unknown', 57, 0.88, 2, 23, 'endpoint', '11434'],
  ['Sider', 'browser_extension', 'unknown', 64, 0.92, 4, 48, 'browser', 'demo-extension-id'],
  ['Perplexity', 'saas_app', 'unknown', 48, 0.71, 5, 96, 'dns', 'perplexity.ai'],
  ['vLLM', 'local_container', 'tolerated', 39, 0.87, 1, 18, 'endpoint', 'vllm/vllm-openai'],
  ['OpenAI API', 'api_service', 'sanctioned', 25, 0.99, 2, 128, 'instrumented', 'gpt-4.1-mini'],
] as const
function seedDetections(): Detection[] {
  return seeds.map(([name, type, classification, risk, confidence, users, events, source, sample], index) => ({
    detection_id: `demo-${index + 1}`, entity_name: name, entity_type: type, entity_category: 'AI assistant', catalog_item_id: `catalog-${index + 1}`,
    classification, shadow_ai_status: classification === 'unsanctioned' ? 'shadow_ai' : 'known', confidence_score: confidence,
    confidence_level: confidence >= .9 ? 'very_high' : 'high', risk_score: risk, risk_level: risk >= 86 ? 'critical' : risk >= 71 ? 'high' : risk >= 51 ? 'medium' : 'low',
    first_seen_at: ago(24 * (index + 2)), last_seen_at: ago(index / 8), impacted_users_count: users, impacted_devices_count: Math.max(1, users - 1), total_events_count: events,
    source_types: [source], primary_evidence: sample, evidence_bundle: {
      [source]: { first_seen: ago(24 * (index + 2)), last_seen: ago(index / 8), matched_field: source === 'endpoint' ? 'process' : 'domain_or_identifier', event_count: events, sample_values: [sample], confidence_base: confidence },
      _users: Array.from({ length: Math.min(users, 4) }, (_, i) => `demo-team-${i + 1}@example.test`),
      ...(type === 'oauth_app' ? { _oauth_scopes: ['Calendars.Read', 'Mail.Read'] } : {}),
      confidence_factors: [{ factor: 'catalog_match', value: confidence, description: 'Catalog identifier match (synthetic)' }],
      risk_factors: [{ factor: 'review_score', value: risk, description: 'Illustrative review-priority score' }],
    }, reasoning_summary: 'Synthetic evidence matched a catalog identifier. A match establishes an observed signal; it does not establish prompt content or data disclosure.',
    analyst_status: index < 2 || index === 3 || index === 5 ? 'new' : 'classified', analyst_notes: null, reviewed_at: null,
    recommended_action: 'Review evidence and organizational approval.', created_at: ago(24 * (index + 2)), updated_at: ago(index / 8),
  }))
}
let detections = seedDetections()
let policies: Governance[] = [{ governance_id: 'demo-policy-1', target_type: 'catalog_item', target_id: 'catalog-3', org_classification: 'sanctioned', owner: 'IT governance', exception_policy: null, enforcement_mode: 'audit', justification: 'Synthetic example of an approved organizational tool.', approved_by: 'Demo reviewer', approved_at: ago(48), approved_until: null, created_by: 'demo-reviewer', created_at: ago(48), updated_at: ago(48) }]
const audit: Array<Record<string, unknown>> = []
export function resetDemo() { detections = seedDetections(); policies = policies.slice(0, 1); audit.length = 0 }
const catalog: CatalogItem[] = seeds.map(([name, type, , , , , , source, sample], i) => ({ catalog_item_id: `catalog-${i + 1}`, canonical_name: name, aliases: [], category: type, vendor: name, description: 'Synthetic demo catalog entry.', domains: ['dns', 'proxy'].includes(source) ? [sample] : [], processes: source === 'endpoint' ? [name.toLowerCase()] : [], url_patterns: [], extension_ids: [], oauth_app_ids: [], local_ports: [], local_paths: [], container_patterns: [], user_agent_patterns: [], rule_tags: [], default_trust_level: 'unknown', status: 'active', source_of_truth: 'synthetic demo', local_override: false, created_at: ago(72), updated_at: ago(2) }))

export function demoRequest(method: string, input: string, body: Record<string, unknown> = {}): unknown {
  const url = new URL(input, 'https://demo.invalid')
  const path = url.pathname
  const params = url.searchParams
  if (path === '/dashboard/summary') return { total: detections.length, unsanctioned: detections.filter(d => d.classification === 'unsanctioned').length, high_risk: detections.filter(d => ['high', 'critical'].includes(d.risk_level)).length, unreviewed: detections.filter(d => d.analyst_status === 'new').length }
  if (path === '/dashboard/trend') return Array.from({ length: 30 }, (_, i) => ({ date: ago((29 - i) * 24).slice(0, 10), count: i > 19 && i < 29 ? 1 : 0 }))
  if (path === '/dashboard/top-tools') return [...detections].sort((a, b) => b.total_events_count - a.total_events_count).slice(0, Number(params.get('limit') || 10)).map(d => ({ name: d.entity_name, entity_type: d.entity_type, classification: d.classification, events_count: d.total_events_count, users_count: d.impacted_users_count, risk_score: d.risk_score }))
  if (path === '/dashboard/source-health') return ['proxy', 'dns', 'endpoint', 'browser', 'oauth', 'instrumented', 'directory'].map((source, i) => ({ source_type: source, status: i === 6 ? 'inactive' : i === 3 ? 'warning' : 'active', last_event: i === 6 ? null : ago(i === 3 ? 8 : .08), events_per_minute: i === 6 ? 0 : [3.2, 1.8, .5, 0, .2, .4][i], events_1h: i === 6 ? 0 : [192, 108, 30, 0, 12, 24][i], window_hours: 1 }))
  if (path === '/dashboard/evidence') return { window_days: 30, window_start: ago(720), window_end: ago(0), total_events: 1777, by_category: [{ category: 'network', events: 1518 }, { category: 'endpoint', events: 89 }, { category: 'oauth', events: 42 }, { category: 'instrumented', events: 128 }], by_source: ['proxy', 'dns', 'endpoint', 'browser', 'oauth', 'instrumented'].map(source => ({ source_type: source, evidence_type: source, events: detections.filter(d => d.source_types.includes(source)).reduce((sum, d) => sum + d.total_events_count, 0) })), models: [{ provider: 'openai', model: 'gpt-4.1-mini', model_provenance: 'instrumented', events: 128 }], measurement: { model_known_events: 128, tokens_reported_events: 128, cost_reported_events: 0, input_tokens: 341200, output_tokens: 98400, cost_usd: null }, unique_users: 31, unique_devices: 27 }
  if (path === '/detections' && method === 'get') {
    let items = detections.filter(d => ['classification', 'risk_level', 'confidence_level', 'entity_type', 'analyst_status'].every(key => !params.get(key) || params.get(key)!.split(',').includes(String(d[key as keyof Detection]))))
    if (params.get('search')) items = items.filter(d => d.entity_name.toLowerCase().includes(params.get('search')!.toLowerCase()))
    const sort = (params.get('sort_by') || 'last_seen_at') as keyof Detection
    const direction = params.get('sort_order') === 'asc' ? 1 : -1
    items = [...items].sort((a, b) => (typeof a[sort] === 'number' ? Number(a[sort]) - Number(b[sort]) : String(a[sort]).localeCompare(String(b[sort]))) * direction)
    const page = Math.max(1, Number(params.get('page') || 1)); const size = Math.max(10, Math.min(100, Number(params.get('page_size') || 25)))
    return { items: items.slice((page - 1) * size, page * size), total: items.length, page, page_size: size }
  }
  if (path.startsWith('/detections/')) {
    const id = path.split('/')[2]; const found = detections.find(d => d.detection_id === id)
    if (!found) throw new Error('Demo detection not found')
    if (path.endsWith('/timeline')) return [{ type: 'first_seen', timestamp: found.first_seen_at, description: 'Synthetic source signal first observed' }, { type: 'last_seen', timestamp: found.last_seen_at, description: 'Most recent synthetic evidence' }]
    if (method === 'patch') {
      Object.assign(found, body, { updated_at: new Date().toISOString(), reviewed_at: new Date().toISOString() })
      audit.unshift({ audit_id: String(audit.length + 1), timestamp: new Date().toISOString(), username: 'Demo reviewer', action: 'detection.update', resource_type: 'detection', resource_id: id, ip_address: null })
    }
    return { ...found }
  }
  if (path === '/catalog') return catalog.filter(item => !params.get('search') || item.canonical_name.toLowerCase().includes(params.get('search')!.toLowerCase()))
  if (path === '/governance') {
    if (method === 'post') policies = [...policies, { ...policies[0], ...body, governance_id: `demo-policy-${policies.length + 1}`, created_at: new Date().toISOString() } as Governance]
    return method === 'post' ? policies[policies.length - 1] : policies
  }
  if (path === '/settings/users') return [{ user_id: 'demo-reviewer', username: 'Demo reviewer', email: 'reviewer@example.test', role: 'admin', is_active: true, last_login_at: ago(0) }]
  if (path === '/audit/logs') return audit
  throw new Error(`Demo route unavailable: ${method} ${path}`)
}
export const demoAdapter: AxiosAdapter = async config => {
  try {
    const body = typeof config.data === 'string' ? JSON.parse(config.data) : config.data
    const data = demoRequest(config.method || 'get', config.url || '/', body)
    return { data, status: 200, statusText: 'OK', headers: new AxiosHeaders(), config }
  } catch (error) { throw new AxiosError(error instanceof Error ? error.message : 'Demo request failed', 'ERR_DEMO', config) }
}
