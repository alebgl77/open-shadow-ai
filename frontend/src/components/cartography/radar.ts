import { NETWORK_PROTOCOLS, type NetworkRelation, type NetworkRelations } from '@/api/network'
import type { CatalogItem } from '@/types'

export const FAMILY_IDS = ['conversation', 'code', 'media', 'other', 'unavailable', 'unassociated'] as const
export type FamilyId = typeof FAMILY_IDS[number]
export type RadarChart = 'protocols' | 'families'
export interface RadarAxis { id: string; observations: number | null; share: number | null; rows: NetworkRelation[] }
export interface RadarData {
  state: 'ready' | 'empty' | 'unavailable'
  reason?: 'network' | 'catalog' | 'counts'
  denominator: number | null
  axes: RadarAxis[]
}
export interface RadarSelection { chart: RadarChart; id: string }

const familyCategories = new Map<string, FamilyId>([
  ...['llm_chat', 'writing_assistant', 'translation_ai', 'search_ai'].map(value => [value, 'conversation'] as const),
  ...['code_assistant', 'agent_automation'].map(value => [value, 'code'] as const),
  ...['image_gen', 'voice_ai', 'video_ai', 'design_ai'].map(value => [value, 'media'] as const),
])

/** Same first-row-wins exact tuple policy as buildGraph; absent IDs normalize to null. */
export const relationKey = (row: NetworkRelation) => JSON.stringify([row.source_ip, row.domain, row.catalog_match_id ?? null, row.protocol])
export function relationFamily(row: NetworkRelation, catalog: ReadonlyMap<string, CatalogItem>): FamilyId {
  if (row.catalog_match_id == null) return 'unassociated'
  const category = catalog.get(row.catalog_match_id)?.category
  if (typeof category !== 'string' || !category.trim()) return 'unavailable'
  return familyCategories.get(category) ?? 'other'
}

const unavailable = (ids: readonly string[], reason: RadarData['reason']): RadarData => ({
  state: 'unavailable', reason, denominator: null,
  axes: ids.map(id => ({ id, observations: null, share: null, rows: [] })),
})

/** Loaded network aggregates only: no graph filters, scene caps or window extrapolation. */
export function buildRadars(network: NetworkRelations | undefined, catalog: CatalogItem[] | undefined): { protocols: RadarData; families: RadarData } {
  if (!network) return { protocols: unavailable(NETWORK_PROTOCOLS, 'network'), families: unavailable(FAMILY_IDS, 'network') }
  const rows = new Map<string, NetworkRelation>()
  let denominator = 0
  for (const row of network.items) {
    // Counts are event counts. Reject unsafe/fractional values, including in duplicate rows.
    if (!Number.isSafeInteger(row.observations) || row.observations < 0 || !NETWORK_PROTOCOLS.includes(row.protocol)) {
      return { protocols: unavailable(NETWORK_PROTOCOLS, 'counts'), families: unavailable(FAMILY_IDS, 'counts') }
    }
    const key = relationKey(row)
    if (rows.has(key)) continue
    denominator += row.observations
    if (!Number.isSafeInteger(denominator)) return { protocols: unavailable(NETWORK_PROTOCOLS, 'counts'), families: unavailable(FAMILY_IDS, 'counts') }
    rows.set(key, row)
  }
  const aggregate = (ids: readonly string[], group: (row: NetworkRelation) => string): RadarData => {
    const axes = new Map(ids.map(id => [id, { id, observations: 0, share: null, rows: [] } as RadarAxis]))
    for (const row of rows.values()) {
      const axis = axes.get(group(row))!
      axis.observations! += row.observations
      axis.rows.push(row)
    }
    for (const axis of axes.values()) axis.share = denominator > 0 ? axis.observations! / denominator : null
    return { state: denominator > 0 ? 'ready' : 'empty', denominator, axes: [...axes.values()] }
  }
  const names = catalog && new Map(catalog.map(item => [item.catalog_item_id, item]))
  return {
    protocols: aggregate(NETWORK_PROTOCOLS, row => row.protocol),
    families: names ? aggregate(FAMILY_IDS, row => relationFamily(row, names)) : unavailable(FAMILY_IDS, 'catalog'),
  }
}
