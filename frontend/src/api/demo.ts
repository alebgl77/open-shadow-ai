import { AxiosError, AxiosHeaders, type AxiosAdapter } from 'axios'
import { ANTI_HR_NOTICE, DETECTION_SORT_COLUMNS, type Detection, type TimelineEntry } from './detections'
import type { Governance, CatalogItem } from '@/types'
import { csvCell } from '@/lib/export'
import { NETWORK_PROTOCOLS, type NetworkEvent, type NetworkProtocol, type NetworkRelation } from './network'
import { CATALOG_MATCHES, ENABLED_STATES, IDENTITY_DAYS_DEFAULT, INSTALL_SOURCES, INVENTORY_SORT_COLUMNS, SORT_ORDERS, enabledState, type ExtensionInventoryItem, type ExtensionVersionChange, type InventorySortColumn, type StoredInstallSource } from './inventory'

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
const catalog: CatalogItem[] = seeds.map(([name, type, , , , , , source, sample], i) => ({ catalog_item_id: `catalog-${i + 1}`, canonical_name: name, aliases: [], category: type, vendor: name, description: 'Synthetic demo catalog entry.', domains: ['dns', 'proxy'].includes(source) ? [sample] : [], processes: source === 'endpoint' ? [name.toLowerCase()] : [], url_patterns: [], extension_ids: source === 'browser' ? [sample] : [], oauth_app_ids: [], local_ports: [], local_paths: [], container_patterns: [], user_agent_patterns: [], rule_tags: [], default_trust_level: 'unknown', status: 'active', source_of_truth: 'synthetic demo', local_override: false, created_at: ago(72), updated_at: ago(2) }))

const networkEvents: NetworkEvent[] = Array.from({ length: 36 }, (_, index) => {
  const protocol = NETWORK_PROTOCOLS[index % NETWORK_PROTOCOLS.length]
  const named = index % 7 !== 0
  const matched = named && index % 5 !== 0
  const domain = !named ? null : matched ? ['chatgpt.com', 'claude.ai', 'copilot.microsoft.com'][index % 3] : 'research.example.test'
  return {
    event_id: `demo-network-${index + 1}`, timestamp: ago(index < 28 ? .25 + index / 2 : 36 + (index - 28) * 14),
    protocol, domain, sni: ['TLS', 'QUIC'].includes(protocol) ? domain : null, url_host: protocol === 'HTTP' ? domain : null,
    src_ip: index % 2 ? '2001:db8:1::25' : '192.0.2.25', dst_ip: index % 2 ? '2001:db8:2::10' : '198.51.100.10',
    dst_port: protocol === 'DNS' ? 53 : protocol === 'HTTP' ? 80 : 443,
    collector_id: index % 2 ? 'demo-lab-02' : 'demo-edge-01', parser_version: 'demo-metadata-1', matched,
    catalog_match_id: matched ? `catalog-${index % 3 + 1}` : null,
    match_field: matched ? 'domain' : null, match_confidence: matched ? .8 : null,
  }
})

// Extension inventory: fictional hosts, opaque user aliases (as a pseudonymised deployment would show) and illustrative versions.
const DEMO_HOSTS = ['demo-host-01', 'demo-host-02', 'demo-host-03']
const DEMO_USERS = ['p1_4f2a9c1e7b3d', 'p1_9d0b7e2c5a81', 'p1_c37e1a8f06d4']
const DEMO_BROWSERS = ['chrome', 'edge', 'firefox', 'safari']
const DEMO_EXTENSIONS: Array<[string, string, boolean]> = [
  ['demo-extension-id', 'Sider', true], ['bfnaelmomeimhlpmgjnjophhpkkoljpa', 'Grammar helper', false], ['cjpalhdlnbpafiamejdnhcphjbkeiagm', 'Tab organizer', false],
  ['{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}', 'Reader mode', false], ['nkbihfbeogaeaoehlefnkodbefgpgknn', 'Clipboard sync', false], ['com.example.safari.notes', 'Notes sidebar', false],
]
const extensionInventory: ExtensionInventoryItem[] = Array.from({ length: 24 }, (_, index) => {
  const [extension_id, extension_name, matched] = DEMO_EXTENSIONS[index % DEMO_EXTENSIONS.length]
  const browser = DEMO_BROWSERS[index % DEMO_BROWSERS.length]
  const legacy = index % 11 === 10 // a host whose agent still sends wire v1 records
  const version = legacy || index % 7 === 6 ? null : `${1 + index % 3}.${index % 5}.${index % 2}`
  return {
    inventory_key: (index + 1).toString(16).padStart(64, '0'), host_label: DEMO_HOSTS[index % DEMO_HOSTS.length],
    user_label: legacy ? null : DEMO_USERS[Math.floor(index / 8)], browser, profile: legacy ? '' : index % 5 === 4 ? 'Profile 1' : 'Default',
    extension_id, extension_name, version, enabled: legacy || index % 3 === 0 ? null : index % 3 === 1,
    install_source: legacy ? '' : INSTALL_SOURCES[index % INSTALL_SOURCES.length],
    installed_at: !legacy && ['chrome', 'edge'].includes(browser) ? ago(24 * (10 + index)) : null,
    first_seen_at: ago(24 * (index % 10 + 1)), last_seen_at: ago(index % 9 === 8 ? 30 : index / 6),
    catalog_item_id: matched ? 'catalog-6' : null, detection_id: matched ? 'demo-6' : null,
    collector_id: `demo-agent-0${index % 3 + 1}`, last_event_id: `demo-inventory-event-${index + 1}`,
    wire_version: legacy ? 1 : 2, present_in_latest_snapshot: index % 9 !== 8,
  }
})
const extensionVersionChanges: ExtensionVersionChange[] = extensionInventory.flatMap((item, index) => item.version === null ? [] : [{
  change_id: `demo-change-${index + 1}`, inventory_key: item.inventory_key, event_id: item.last_event_id,
  extension_id: item.extension_id, extension_name: item.extension_name, browser: item.browser, host_label: item.host_label, user_label: item.user_label, profile: item.profile,
  from_version: index % 6 === 0 ? null : `${1 + index % 3}.${Math.max(0, index % 5 - 1)}.0`, to_version: item.version,
  previous_observed_at: ago(index * 9 + 12), observed_at: ago(index * 9 + .5), catalog_item_id: item.catalog_item_id,
}])
// What the correlator keeps for a catalog-matched extension: the newest ten changes and hosts per version, no host or user.
function demoVersionEvidence(catalogItemId: string | null) {
  const changes = extensionVersionChanges.filter(change => catalogItemId !== null && change.catalog_item_id === catalogItemId)
    .sort((a, b) => b.observed_at.localeCompare(a.observed_at)).slice(0, 10)
  const hosts = new Map<string, Set<string>>()
  for (const item of extensionInventory.filter(row => catalogItemId !== null && row.catalog_item_id === catalogItemId)) {
    hosts.set(item.version ?? '', (hosts.get(item.version ?? '') ?? new Set()).add(item.host_label))
  }
  return { changes, versions: Object.fromEntries([...hosts].map(([version, names]) => [version, names.size])) }
}
function withVersionEvidence(detection: Detection): Detection {
  const browser = detection.evidence_bundle.browser
  if (!browser || typeof browser !== 'object' || Array.isArray(browser)) return detection
  const { changes, versions } = demoVersionEvidence(detection.catalog_item_id)
  const version_changes = [...changes].reverse().map(({ from_version, to_version, observed_at }) => ({ from_version, to_version, observed_at }))
  return { ...detection, evidence_bundle: { ...detection.evidence_bundle, browser: { ...browser, version_changes, versions } } }
}
function demoTimeline(detection: Detection): TimelineEntry[] {
  const changes = demoVersionEvidence(detection.catalog_item_id).changes.map(change => ({
    type: 'extension_version_change', timestamp: change.observed_at, browser: change.browser, from_version: change.from_version, to_version: change.to_version,
    description: `${change.browser} extension updated ${change.from_version ?? 'not reported'} -> ${change.to_version ?? 'not reported'}`,
  }))
  return [
    { type: 'first_seen', timestamp: detection.first_seen_at, description: 'Synthetic source signal first observed' },
    { type: 'last_seen', timestamp: detection.last_seen_at, description: 'Most recent synthetic evidence' }, ...changes,
  ].sort((a, b) => a.timestamp.localeCompare(b.timestamp))
}
const identityWindow = () => ({ days: IDENTITY_DAYS_DEFAULT, as_of: new Date().toISOString() })
const IDENTITY_MODE = 'pseudonymized' as const

function pageOf<T>(items: T[], params: URLSearchParams) {
  const page = Math.max(1, Number(params.get('page') || 1))
  const page_size = Math.max(1, Math.min(100, Number(params.get('page_size') || 25)))
  return { items: items.slice((page - 1) * page_size, page * page_size), total: items.length, page, page_size }
}

function inventoryRows(params: URLSearchParams): ExtensionInventoryItem[] {
  let items = extensionInventory
  const host = params.get('host'); const browser = params.get('browser'); const enabled = params.get('enabled'); const source = params.get('install_source')
  const match = params.get('catalog_match'); const id = params.get('extension_id'); const search = params.get('search')?.toLowerCase()
  if (host) items = items.filter(item => item.host_label.toLowerCase().includes(host.toLowerCase()))
  if (browser) items = items.filter(item => browser.split(',').includes(item.browser))
  if (enabled) {
    if (!(ENABLED_STATES as readonly string[]).includes(enabled)) throw new Error('Invalid inventory filter')
    items = items.filter(item => enabledState(item.enabled) === enabled)
  }
  if (source) {
    const sources = source.split(',')
    if (sources.some(value => !(INSTALL_SOURCES as readonly string[]).includes(value))) throw new Error('Invalid install source')
    items = items.filter(item => sources.includes(item.install_source))
  }
  if (match) {
    if (!(CATALOG_MATCHES as readonly string[]).includes(match)) throw new Error('Invalid inventory filter')
    items = items.filter(item => (item.catalog_item_id !== null) === (match === 'matched'))
  }
  if (id) items = items.filter(item => item.extension_id === id)
  if (search) items = items.filter(item => item.extension_name.toLowerCase().includes(search) || item.extension_id.toLowerCase().includes(search))
  const sort = params.get('sort_by') || 'last_seen_at'; const order = params.get('sort_order') || 'desc'
  if (!(INVENTORY_SORT_COLUMNS as readonly string[]).includes(sort) || !(SORT_ORDERS as readonly string[]).includes(order)) throw new Error('Invalid sort')
  const column = sort as InventorySortColumn; const direction = order === 'asc' ? 1 : -1
  return [...items].sort((a, b) => {
    const left = a[column]; const right = b[column]
    if (left === null || right === null) return left === right ? 0 : left === null ? 1 : -1 // "Not reported" stays last either way
    return String(left).localeCompare(String(right)) * direction || a.inventory_key.localeCompare(b.inventory_key)
  })
}

function inventorySummary() {
  const by_install_source = Object.fromEntries(['', ...INSTALL_SOURCES].map(source => [source, 0])) as Record<StoredInstallSource, number>
  const by_browser: Record<string, number> = {}; const by_enabled = { true: 0, false: 0, unknown: 0 }
  for (const item of extensionInventory) {
    by_install_source[item.install_source] += 1
    by_browser[item.browser] = (by_browser[item.browser] || 0) + 1
    by_enabled[enabledState(item.enabled)] += 1
  }
  return {
    installations: extensionInventory.length, hosts: new Set(extensionInventory.map(item => item.host_label)).size,
    extensions: new Set(extensionInventory.map(item => item.extension_id)).size, catalog_matched: extensionInventory.filter(item => item.catalog_item_id).length,
    by_enabled, by_browser: Object.fromEntries(Object.entries(by_browser).sort()), by_install_source,
    version_changes_7d: extensionVersionChanges.filter(change => Date.parse(change.observed_at) >= Date.now() - 7 * 86400000).length,
    identity_window: identityWindow(), identity_mode: IDENTITY_MODE,
    limitations: ['These hosts, users and installations are fictional.', 'Installation is presence evidence, not usage; the inventory supports incident review, not employee monitoring.', 'Only hosts running the endpoint agent with browser collection are covered; other browsers and hosts are unknown.', 'Installations and version history are kept for the identity retention window only.'],
  }
}

function networkInWindow(params: URLSearchParams) {
  const hours = Number(params.get('hours') || 24)
  if (!Number.isInteger(hours) || hours < 1 || hours > 168) throw new Error('Invalid network observation window')
  return networkEvents.filter(event => Date.parse(event.timestamp) >= NOW - hours * 3600000)
}

function filteredNetwork(params: URLSearchParams) {
  const protocol = params.get('protocol')
  if (protocol && !NETWORK_PROTOCOLS.includes(protocol as NetworkProtocol)) throw new Error('Invalid network protocol')
  return [...new Map(networkInWindow(params).map(event => [event.event_id, event])).values()].filter(event =>
    (!protocol || event.protocol === protocol) &&
    (!params.has('source_ip') || (event.src_ip || '') === params.get('source_ip')) &&
    (!params.has('catalog_match_id') || (event.catalog_match_id || '') === params.get('catalog_match_id')) &&
    (!params.has('domain') || (event.domain || event.sni || event.url_host || '') === params.get('domain')))
}

function matchingDetections(params: URLSearchParams, defaultSort: keyof Detection): Detection[] {
  let items = detections.filter(d => ['classification', 'risk_level', 'confidence_level', 'entity_type', 'analyst_status'].every(key => !params.get(key) || params.get(key)!.split(',').includes(String(d[key as keyof Detection]))))
  if (params.get('search')) items = items.filter(d => d.entity_name.toLowerCase().includes(params.get('search')!.toLowerCase()))
  const sort = (params.get('sort_by') || defaultSort) as keyof Detection
  if (!(DETECTION_SORT_COLUMNS as readonly string[]).includes(sort)) throw new Error('Invalid sort')
  const direction = params.get('sort_order') === 'asc' ? 1 : -1
  return [...items].sort((a, b) => (typeof a[sort] === 'number' ? Number(a[sort]) - Number(b[sort]) : String(a[sort]).localeCompare(String(b[sort]))) * direction)
}

export function demoRequest(method: string, input: string, body: Record<string, unknown> = {}): unknown {
  const url = new URL(input, 'https://demo.invalid')
  const path = url.pathname
  const params = url.searchParams
  if (path === '/dashboard/summary') return { total: detections.length, unsanctioned: detections.filter(d => d.classification === 'unsanctioned').length, high_risk: detections.filter(d => ['high', 'critical'].includes(d.risk_level)).length, unreviewed: detections.filter(d => d.analyst_status === 'new').length }
  if (path === '/dashboard/trend') return Array.from({ length: 30 }, (_, i) => ({ date: ago((29 - i) * 24).slice(0, 10), count: i > 19 && i < 29 ? 1 : 0 }))
  if (path === '/dashboard/top-tools') return [...detections].sort((a, b) => b.total_events_count - a.total_events_count).slice(0, Number(params.get('limit') || 10)).map(d => ({ name: d.entity_name, entity_type: d.entity_type, classification: d.classification, events_count: d.total_events_count, users_count: d.impacted_users_count, risk_score: d.risk_score }))
  if (path === '/dashboard/source-health') return [...['proxy', 'dns', 'endpoint', 'browser', 'oauth', 'instrumented', 'directory'].map((source, i) => ({ source_type: source, status: i === 6 ? 'inactive' : i === 3 ? 'warning' : 'active', last_event: i === 6 ? null : ago(i === 3 ? 8 : .08), events_per_minute: i === 6 ? 0 : [3.2, 1.8, .5, 0, .2, .4][i], events_1h: i === 6 ? 0 : [192, 108, 30, 0, 12, 24][i], window_hours: 1 })), { source_type: 'network', status: 'active', last_event: networkEvents[0].timestamp, events_per_minute: 2 / 60, events_1h: 2, window_hours: 1 }]
  if (path === '/dashboard/evidence') return { window_days: 30, window_start: ago(720), window_end: ago(0), total_events: 1777 + networkEvents.length, by_category: [{ category: 'network', events: 1518 + networkEvents.length }, { category: 'endpoint', events: 89 }, { category: 'oauth', events: 42 }, { category: 'instrumented', events: 128 }], by_source: ['proxy', 'dns', 'endpoint', 'browser', 'oauth', 'instrumented', 'network'].map(source => ({ source_type: source, evidence_type: source, events: source === 'network' ? networkEvents.length : detections.filter(d => d.source_types.includes(source)).reduce((sum, d) => sum + d.total_events_count, 0) })), models: [{ provider: 'openai', model: 'gpt-4.1-mini', model_provenance: 'instrumented', events: 128 }], measurement: { model_known_events: 128, tokens_reported_events: 128, cost_reported_events: 0, input_tokens: 341200, output_tokens: 98400, cost_usd: null }, unique_users: 31, unique_devices: 27 }
  if (path === '/network/overview') {
    const events = networkInWindow(params)
    return {
      hours: Number(params.get('hours') || 24), total_observations: events.length,
      named_observations: events.filter(event => event.domain).length, matched_observations: events.filter(event => event.matched).length,
      unmatched_observations: events.filter(event => !event.matched).length,
      protocols: Object.fromEntries(NETWORK_PROTOCOLS.map(protocol => [protocol, events.filter(event => event.protocol === protocol).length])),
      sensors: [...new Set(events.map(event => event.collector_id))].map(collector_id => {
        const observations = events.filter(event => event.collector_id === collector_id)
        return { collector_id, last_seen: observations[0].timestamp, observations: observations.length }
      }),
      limitations: ['These observations and sensors are fictional.', 'Imported metadata covers only the configured collection points.', 'DNS is weaker evidence than an observed connection. Protocols remain one network source.', 'No user, model, prompt or token attribution is inferred from network addresses.'],
    }
  }
  if (path === '/network/relations') {
    const events = filteredNetwork(params)
    const grouped = new Map<string, NetworkRelation>()
    for (const event of events) {
      const source_ip = event.src_ip || '', domain = event.domain || event.sni || event.url_host || ''
      const key = JSON.stringify([source_ip, domain, event.catalog_match_id, event.protocol])
      const prior = grouped.get(key)
      if (prior) {
        prior.observations++
        prior.first_seen = prior.first_seen < event.timestamp ? prior.first_seen : event.timestamp
        prior.last_seen = prior.last_seen > event.timestamp ? prior.last_seen : event.timestamp
      } else grouped.set(key, { source_ip, domain, catalog_match_id: event.catalog_match_id, protocol: event.protocol, observations: 1, first_seen: event.timestamp, last_seen: event.timestamp })
    }
    const limit = Number(params.get('limit') || 300)
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new Error('Invalid relation limit')
    const items = [...grouped].sort(([a], [b]) => a.localeCompare(b)).slice(0, limit).map(([, item]) => item)
    return { hours: Number(params.get('hours') || 24), protocol: params.get('protocol'), items, total_observations: events.length, total_relations: grouped.size, represented_observations: items.reduce((sum, item) => sum + item.observations, 0), represented_relations: items.length, truncated: grouped.size > items.length, limitations: ['These observations and sensors are fictional.', 'Imported metadata covers only the configured collection points.', 'No user, model, prompt or token attribution is inferred from network addresses.'] }
  }
  if (path.startsWith('/network/events/')) {
    const found = networkInWindow(params).find(event => event.event_id === decodeURIComponent(path.slice('/network/events/'.length)))
    if (!found) throw new Error('Network event not found')
    return { ...found }
  }
  if (path === '/network/events') {
    const events = filteredNetwork(params)
    const page = Math.max(1, Number(params.get('page') || 1))
    const page_size = Math.max(1, Math.min(100, Number(params.get('page_size') || 20)))
    return { items: events.slice((page - 1) * page_size, page * page_size), total: events.length, page, page_size }
  }
  if (path === '/extensions/inventory/summary') return inventorySummary()
  if (path === '/extensions/inventory') return { ...pageOf(inventoryRows(params), params), identity_window: identityWindow(), identity_mode: IDENTITY_MODE }
  if (path.startsWith('/extensions/inventory/') && path.endsWith('/versions')) {
    const key = decodeURIComponent(path.split('/')[3]); const installation = extensionInventory.find(item => item.inventory_key === key)
    if (!installation) throw new Error('Demo installation not found')
    const changes = extensionVersionChanges.filter(change => change.inventory_key === key).sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at))
    return { installation, changes, identity_window: identityWindow(), identity_mode: IDENTITY_MODE }
  }
  if (path === '/extensions/version-changes') {
    const now = Date.now(); const cutoff = now - IDENTITY_DAYS_DEFAULT * 86400000
    const bound = (name: string, fallback: number) => { const raw = params.get(name); if (!raw) return fallback; const value = Date.parse(raw); if (!Number.isFinite(value)) throw new Error('Invalid version change window'); return value }
    const since = Math.max(bound('since', cutoff), cutoff); const until = Math.min(bound('until', now), now)
    const browser = params.get('browser'); const host = params.get('host'); const id = params.get('extension_id')
    const changes = extensionVersionChanges.filter(change => { const observed = Date.parse(change.observed_at); return observed >= since && observed <= until })
      .filter(change => (!browser || browser.split(',').includes(change.browser)) && (!host || change.host_label.toLowerCase().includes(host.toLowerCase())) && (!id || change.extension_id === id))
      .sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at))
    return { ...pageOf(changes, params), since: new Date(since).toISOString(), until: new Date(until).toISOString(), identity_window: identityWindow(), identity_mode: IDENTITY_MODE }
  }
  if (path === '/exports/extension-inventory' && method === 'post') {
    const items = inventoryRows(params)
    const filters = Object.fromEntries([...params].filter(([key]) => !['format', 'sort_by', 'sort_order'].includes(key)))
    audit.unshift({ audit_id: String(audit.length + 1), timestamp: new Date().toISOString(), username: 'Demo reviewer', action: 'export_extension_inventory', resource_type: null, resource_id: null, ip_address: null, details: { format: 'csv', count: items.length, filters } })
    const rows = [['host_label', 'user_label', 'browser', 'profile', 'extension_id', 'extension_name', 'version', 'enabled', 'install_source', 'installed_at', 'first_seen_at', 'last_seen_at', 'present_in_latest_snapshot', 'catalog_item_id'], ...items.map(item => [item.host_label, item.user_label ?? '', item.browser, item.profile, item.extension_id, item.extension_name, item.version ?? '', enabledState(item.enabled), item.install_source, item.installed_at ?? '', item.first_seen_at, item.last_seen_at, item.present_in_latest_snapshot, item.catalog_item_id ?? ''])]
    return `# WARNING: Synthetic demo export. ${ANTI_HR_NOTICE}\n` + rows.map(row => row.map(csvCell).join(',')).join('\r\n')
  }
  if (path === '/detections' && method === 'get') {
    const items = matchingDetections(params, 'last_seen_at')
    const page = Math.max(1, Number(params.get('page') || 1)); const size = Math.max(10, Math.min(100, Number(params.get('page_size') || 25)))
    return { items: items.slice((page - 1) * size, page * size), total: items.length, page, page_size: size }
  }
  if (path === '/exports/detections' && method === 'post') {
    const items = matchingDetections(params, 'risk_score')
    const filters = Object.fromEntries([...params].filter(([key]) => key !== 'format'))
    audit.unshift({ audit_id: String(audit.length + 1), timestamp: new Date().toISOString(), username: 'Demo reviewer', action: 'export_detections', resource_type: null, resource_id: null, ip_address: null, details: { format: 'csv', count: items.length, filters } })
    const rows = [['entity_name', 'entity_type', 'classification', 'risk_score', 'impacted_users', 'last_seen'], ...items.map(d => [d.entity_name, d.entity_type, d.classification, d.risk_score, d.impacted_users_count, d.last_seen_at])]
    return `# WARNING: Synthetic demo export. ${ANTI_HR_NOTICE}\n` + rows.map(row => row.map(csvCell).join(',')).join('\r\n')
  }
  if (path.startsWith('/detections/')) {
    const id = path.split('/')[2]; const found = detections.find(d => d.detection_id === id)
    if (!found) throw new Error('Demo detection not found')
    if (path.endsWith('/timeline')) return demoTimeline(found)
    if (method === 'patch') {
      Object.assign(found, body, { updated_at: new Date().toISOString(), reviewed_at: new Date().toISOString() })
      audit.unshift({ audit_id: String(audit.length + 1), timestamp: new Date().toISOString(), username: 'Demo reviewer', action: 'detection.update', resource_type: 'detection', resource_id: id, ip_address: null })
    }
    return withVersionEvidence({ ...found })
  }
  if (path === '/catalog') return catalog.filter(item => !params.get('search') || item.canonical_name.toLowerCase().includes(params.get('search')!.toLowerCase()))
  if (path.startsWith('/catalog/')) {
    const item = catalog.find(item => item.catalog_item_id === decodeURIComponent(path.slice('/catalog/'.length)))
    if (!item) throw new Error('Demo catalog item not found')
    return { ...item }
  }
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
  } catch (error) {
    const notFound = error instanceof Error && error.message === 'Network event not found'
    throw new AxiosError(error instanceof Error ? error.message : 'Demo request failed', 'ERR_DEMO', config, undefined, notFound ? { data: { detail: 'Network event not found' }, status: 404, statusText: 'Not Found', headers: new AxiosHeaders(), config } : undefined)
  }
}
