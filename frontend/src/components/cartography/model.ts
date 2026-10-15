import type { ExtensionInventoryItem } from '@/api/inventory'
import type { NetworkRelation, NetworkRelations } from '@/api/network'
import type { CatalogItem } from '@/types'

export type NodeKind = 'ip' | 'host' | 'service' | 'unmatched'
export type EdgeKind = 'network' | 'installation'
export interface GraphNode {
  id: string; kind: NodeKind; label: string; value: string; collector?: string
  catalogId?: string; category?: string; position: [number, number, number]
}
export interface GraphEdge {
  id: string; kind: EdgeKind; source: string; target: string
  network?: NetworkRelation; installations: ExtensionInventoryItem[]
}
export interface Graph {
  nodes: GraphNode[]; edges: GraphEdge[]
  eligibleNodes: number; eligibleEdges: number; omittedNodes: number; omittedEdges: number
  representedObservations: number; representedInstallations: number
}
export interface GraphFilters { kind: 'all' | EdgeKind; category: string; search: string }
export const NODE_CAP = 160
export const EDGE_CAP = 320
export const graphId = (...parts: Array<string | null>) => JSON.stringify(parts)
/** Bounded depth fan: many domain tuples can share exactly one endpoint pair. */
export const curveOffset = (ordinal: number): [number, number] => [8 + Math.sin(ordinal * 2.3999632297) * 18, 20 + Math.cos(ordinal * 2.3999632297) * 22]

/** Exact IDs create associations. Source addresses never identify inventory hosts. */
export function buildGraph(network: NetworkRelations | undefined, inventory: ExtensionInventoryItem[], catalog: CatalogItem[], filters: GraphFilters): Graph {
  const names = new Map(catalog.map(item => [item.catalog_item_id, item]))
  const nodes = new Map<string, GraphNode>(), edges = new Map<string, GraphEdge>()
  const addNode = (id: string, kind: NodeKind, value: string, extra: Partial<GraphNode> = {}) => {
    if (!nodes.has(id)) nodes.set(id, { id, kind, value, label: value, position: [0, 0, 0], ...extra })
    return id
  }
  const service = (id: string) => addNode(graphId('catalog', id), 'service', id, { label: names.get(id)?.canonical_name || id, catalogId: id, category: names.get(id)?.category })
  for (const row of network?.items || []) {
    const source = addNode(graphId('ip', row.source_ip), 'ip', row.source_ip)
    const target = row.catalog_match_id ? service(row.catalog_match_id) : addNode(graphId('unmatched-network', row.domain), 'unmatched', row.domain)
    const id = graphId('network', row.source_ip, row.domain, row.catalog_match_id, row.protocol)
    // Duplicate aggregate rows are not additional observations.
    if (!edges.has(id)) edges.set(id, { id, kind: 'network', source, target, network: row, installations: [] })
  }
  const installed = new Set<string>()
  for (const item of inventory) {
    if (installed.has(item.inventory_key)) continue
    installed.add(item.inventory_key)
    const source = addNode(graphId('reported-host', item.collector_id, item.host_label), 'host', item.host_label, { collector: item.collector_id })
    const target = item.catalog_item_id ? service(item.catalog_item_id) : addNode(graphId('unmatched-extension', item.extension_id), 'unmatched', item.extension_name || item.extension_id)
    const id = graphId('installation', source, target)
    const prior = edges.get(id)
    if (prior) prior.installations.push(item)
    else edges.set(id, { id, kind: 'installation', source, target, installations: [item] })
  }
  const search = filters.search.toLocaleLowerCase().trim()
  const eligible = [...edges.values()].sort((a, b) => a.id.localeCompare(b.id)).filter(edge => {
    const from = nodes.get(edge.source)!, to = nodes.get(edge.target)!
    return (filters.kind === 'all' || edge.kind === filters.kind) &&
      (!filters.category || to.category === filters.category) &&
      (!search || [from.label, from.value, from.collector || '', to.label, to.value, edge.network?.domain || ''].some(text => text.toLocaleLowerCase().includes(search)))
  })
  const eligibleNodeIds = new Set(eligible.flatMap(edge => [edge.source, edge.target]))
  const visible = new Set<string>(), result: GraphEdge[] = []
  for (const edge of eligible) {
    const additions = [edge.source, edge.target].filter(id => !visible.has(id))
    if (result.length >= EDGE_CAP || visible.size + new Set(additions).size > NODE_CAP) continue
    visible.add(edge.source); visible.add(edge.target); result.push(edge)
  }
  const resultNodes = [...visible].sort().map(id => nodes.get(id)!)
  for (const kind of ['ip', 'host', 'service', 'unmatched'] as NodeKind[]) {
    const group = resultNodes.filter(node => node.kind === kind)
    group.forEach((node, index) => {
      const angle = index * Math.PI * 2 / Math.max(1, group.length)
      const ring = Math.floor(index / 16)
      const radius = group.length > 1 ? 22 + ring * 9 : 0
      node.position = [kind === 'ip' ? -64 : kind === 'host' ? -46 : kind === 'service' ? 38 : 76,
        (kind === 'host' ? -35 : kind === 'ip' ? 30 : 4) + Math.sin(angle) * radius,
        Math.cos(angle) * radius + (kind === 'host' ? 20 : kind === 'unmatched' ? -25 : 0)]
      if (group.length <= 12) {
        // Distinct projected rows keep small real-world/demo cohorts readable from the initial camera.
        const spacing = kind === 'ip' ? 44 : kind === 'host' ? 22 : kind === 'service' ? 24 : 18
        node.position = [kind === 'ip' ? -64 : kind === 'host' ? -48 : kind === 'service' ? 35 : 82,
          (kind === 'host' ? -43 : kind === 'ip' ? 27 : 0) + (index - (group.length - 1) / 2) * spacing,
          (kind === 'host' ? 24 : kind === 'unmatched' ? -25 : 0) + Math.sin(index * 2.4) * 12]
      }
    })
  }
  return { nodes: resultNodes, edges: result, eligibleNodes: eligibleNodeIds.size, eligibleEdges: eligible.length,
    omittedNodes: eligibleNodeIds.size - visible.size, omittedEdges: eligible.length - result.length,
    representedObservations: result.reduce((sum, edge) => sum + (edge.network?.observations || 0), 0),
    representedInstallations: result.reduce((sum, edge) => sum + edge.installations.length, 0) }
}

export type Selection = { kind: 'node' | 'edge'; id: string } | null
export const neighbors = (graph: Graph, selected: Selection) => selected?.kind === 'node'
  ? graph.edges.filter(edge => edge.source === selected.id || edge.target === selected.id)
  : graph.edges.filter(edge => edge.id === selected?.id)
