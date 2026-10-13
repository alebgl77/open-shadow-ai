import client from './client'

// Mirrors EXTENSION_INSTALL_SOURCES in src/shadai/models/event.py; tests/test_catalog_dashboard.py parses this literal.
export const INSTALL_SOURCES = ['store', 'user', 'unpacked', 'external', 'policy', 'component', 'orphan', 'unknown'] as const
export type InstallSource = typeof INSTALL_SOURCES[number]
/** '' is the install source of a record a wire v1 agent sent without any state ("Not reported"). */
export type StoredInstallSource = InstallSource | ''
// The `enabled` filter vocabulary of the API; "unknown" selects installations whose agent reported no state.
export const ENABLED_STATES = ['true', 'false', 'unknown'] as const
export type EnabledState = typeof ENABLED_STATES[number]
export const CATALOG_MATCHES = ['matched', 'unmatched'] as const
export type CatalogMatch = typeof CATALOG_MATCHES[number]
// Mirrors INVENTORY_SORT_COLUMNS in src/shadai/api/extensions.py; the API rejects any other value.
export const INVENTORY_SORT_COLUMNS = ['last_seen_at', 'first_seen_at', 'extension_name', 'browser', 'version', 'installed_at', 'host_label'] as const
export type InventorySortColumn = typeof INVENTORY_SORT_COLUMNS[number]
export const SORT_ORDERS = ['asc', 'desc'] as const
export type SortOrder = typeof SORT_ORDERS[number]
export const INVENTORY_WINDOWS = [24, 72, 168] as const
export const INVENTORY_NOTICE = 'An installation is presence evidence, not usage. The inventory holds the state each endpoint agent last reported per host, user, browser and profile; it supports incident review, not employee monitoring.'
export const IDENTITY_DAYS_DEFAULT = 30

export interface IdentityWindow { days: number; as_of: string }
export type IdentityMode = 'pseudonymized' | 'raw'

export interface ExtensionInventoryItem {
  inventory_key: string
  host_label: string
  user_label: string | null
  browser: string
  profile: string
  extension_id: string
  extension_name: string
  version: string | null
  enabled: boolean | null
  install_source: StoredInstallSource
  installed_at: string | null
  first_seen_at: string
  last_seen_at: string
  catalog_item_id: string | null
  detection_id: string | null
  collector_id: string
  last_event_id: string
  wire_version: number
  present_in_latest_snapshot: boolean
}

export interface ExtensionVersionChange {
  change_id: string
  inventory_key: string
  event_id: string
  extension_id: string
  extension_name: string
  browser: string
  host_label: string
  user_label: string | null
  profile: string
  from_version: string | null
  to_version: string | null
  previous_observed_at: string
  observed_at: string
  catalog_item_id: string | null
}

export interface ExtensionInventoryPage {
  items: ExtensionInventoryItem[]
  total: number
  page: number
  page_size: number
  identity_window: IdentityWindow
  identity_mode: IdentityMode
}

export interface InventorySummary {
  installations: number
  hosts: number
  extensions: number
  catalog_matched: number
  by_enabled: Record<EnabledState, number>
  by_browser: Record<string, number>
  by_install_source: Record<StoredInstallSource, number>
  version_changes_7d: number
  identity_window: IdentityWindow
  identity_mode: IdentityMode
  limitations: string[]
}

export interface InstallationHistory {
  installation: ExtensionInventoryItem
  changes: ExtensionVersionChange[]
  identity_window: IdentityWindow
  identity_mode: IdentityMode
}

export interface VersionChangePage {
  items: ExtensionVersionChange[]
  total: number
  page: number
  page_size: number
  since: string | null
  until: string | null
  identity_window: IdentityWindow
  identity_mode: IdentityMode
}

export const INVENTORY_FILTER_KEYS = ['host', 'browser', 'enabled', 'install_source', 'catalog_match', 'extension_id', 'search'] as const
export type InventoryFilterKey = typeof INVENTORY_FILTER_KEYS[number]

export interface InventoryFilters {
  host?: string
  browser?: string
  enabled?: EnabledState
  install_source?: string
  catalog_match?: CatalogMatch
  extension_id?: string
  search?: string
  page: number
  page_size: number
  sort_by: InventorySortColumn
  sort_order: SortOrder
}

export interface VersionChangeFilters {
  hours: number
  host?: string
  browser?: string
  extension_id?: string
  page: number
  page_size: number
}

function inventoryParams(filters: InventoryFilters) {
  const params = new URLSearchParams()
  INVENTORY_FILTER_KEYS.forEach(key => { const value = filters[key]; if (value) params.set(key, value) })
  return params
}

export function getExtensionInventory(filters: InventoryFilters, signal?: AbortSignal) {
  const params = inventoryParams(filters)
  params.set('page', String(filters.page)); params.set('page_size', String(filters.page_size))
  params.set('sort_by', filters.sort_by); params.set('sort_order', filters.sort_order)
  return client.get<ExtensionInventoryPage>(`/extensions/inventory?${params}`, { signal }).then(response => response.data)
}

export const getInventorySummary = (signal?: AbortSignal) =>
  client.get<InventorySummary>('/extensions/inventory/summary', { signal }).then(response => response.data)

export const getExtensionVersions = (inventoryKey: string, signal?: AbortSignal) =>
  client.get<InstallationHistory>(`/extensions/inventory/${encodeURIComponent(inventoryKey)}/versions`, { signal }).then(response => response.data)

/** Changes observed in the last `hours`; the server clamps the window to the identity retention window. */
export function getVersionChanges(filters: VersionChangeFilters, signal?: AbortSignal) {
  const params = new URLSearchParams({ since: new Date(Date.now() - filters.hours * 3600000).toISOString() })
  for (const key of ['host', 'browser', 'extension_id'] as const) { if (filters[key]) params.set(key, filters[key]) }
  params.set('page', String(filters.page)); params.set('page_size', String(filters.page_size))
  return client.get<VersionChangePage>(`/extensions/version-changes?${params}`, { signal }).then(response => response.data)
}

/** Every installation matching the filters, exported and audited by the server (analyst role). */
export async function exportExtensionInventory(filters: InventoryFilters): Promise<{ blob: Blob; filename: string }> {
  const params = new URLSearchParams({ format: 'csv' })
  inventoryParams(filters).forEach((value, key) => params.set(key, value))
  params.set('sort_by', filters.sort_by); params.set('sort_order', filters.sort_order)
  const response = await client.post<Blob | string>(`/exports/extension-inventory?${params}`, undefined, { responseType: 'blob' })
  const disposition = String(response.headers?.['content-disposition'] ?? '')
  const suggested = /filename="?([^";]+)"?/i.exec(disposition)?.[1] ?? 'open-shadow-ai-extension-inventory.csv'
  const blob = response.data instanceof Blob ? response.data : new Blob([String(response.data)], { type: 'text/csv;charset=utf-8;' })
  return { blob, filename: suggested.replace(/[^\w.-]/g, '_') }
}

/** The `enabled` filter value an installation would match. */
export const enabledState = (enabled: boolean | null): EnabledState => enabled === true ? 'true' : enabled === false ? 'false' : 'unknown'
