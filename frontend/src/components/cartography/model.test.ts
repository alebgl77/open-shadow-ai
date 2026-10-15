import { describe, expect, it } from 'vitest'
import { buildGraph, curveOffset, EDGE_CAP, NODE_CAP } from './model'
import type { NetworkRelation, NetworkRelations } from '@/api/network'
import type { ExtensionInventoryItem } from '@/api/inventory'
import type { CatalogItem } from '@/types'

const relation = (overrides: Partial<NetworkRelation> = {}): NetworkRelation => ({ source_ip: '192.0.2.1', domain: 'ai.example.test', catalog_match_id: 'catalog-1', protocol: 'TLS', observations: 4, first_seen: '2026-10-15T00:00:00Z', last_seen: '2026-10-15T01:00:00Z', ...overrides })
const envelope = (items: NetworkRelation[]): NetworkRelations => ({ hours: 24, protocol: null, items, total_observations: items.reduce((sum, item) => sum + item.observations, 0), total_relations: items.length, represented_observations: 4, represented_relations: items.length, truncated: false, limitations: [] })
const install = (overrides: Partial<ExtensionInventoryItem> = {}): ExtensionInventoryItem => ({ inventory_key: 'key-1', host_label: '192.0.2.1', collector_id: 'collector-1', catalog_item_id: 'catalog-1', extension_id: 'ext-1', extension_name: 'Extension', ...overrides } as ExtensionInventoryItem)
const catalog = [{ catalog_item_id: 'catalog-1', canonical_name: 'Service', category: 'code_assistant' }] as CatalogItem[]
const filters = { kind: 'all' as const, category: '', search: '' }

describe('cartography evidence graph', () => {
  it('shares an authoritative catalog ID while keeping equal IP and reported-host labels distinct', () => {
    const graph = buildGraph(envelope([relation()]), [install()], catalog, filters)
    expect(graph.nodes.map(node => node.kind).sort()).toEqual(['host', 'ip', 'service'])
    expect(graph.edges.map(edge => edge.kind).sort()).toEqual(['installation', 'network'])
    expect(new Set(graph.edges.map(edge => edge.target)).size).toBe(1)
    expect(graph.edges.every(edge => graph.nodes.find(node => node.id === edge.target)?.kind === 'service')).toBe(true)
    expect(graph.edges[0].source).not.toBe(graph.edges[1].source)
    expect(graph.representedObservations).toBe(4)
    expect(graph.representedInstallations).toBe(1)
  })
  it('collector-scopes repeated host labels and preserves anonymous sources and unmatched hosts', () => {
    const graph = buildGraph(envelope([relation({ source_ip: '', catalog_match_id: null, domain: '' })]), [install(), install({ inventory_key: 'key-2', collector_id: 'collector-2' })], catalog, filters)
    expect(graph.nodes.filter(node => node.kind === 'host')).toHaveLength(2)
    expect(graph.nodes.find(node => node.kind === 'ip')?.value).toBe('')
    expect(graph.nodes.find(node => node.kind === 'unmatched')?.value).toBe('')
    expect(graph.nodes.filter(node => node.catalogId)).toHaveLength(1)
  })
  it('does not collide on delimiters, prototype keys or network/extension namespaces', () => {
    const graph = buildGraph(envelope([relation({ source_ip: 'a|b', domain: 'c', catalog_match_id: null }), relation({ source_ip: 'a', domain: 'b|c', catalog_match_id: null }), relation({ source_ip: '__proto__', domain: 'toString', catalog_match_id: null })]), [install({ catalog_item_id: null, extension_id: 'toString' })], [], filters)
    expect(graph.edges).toHaveLength(4)
    expect(new Set(graph.edges.map(edge => edge.id)).size).toBe(4)
    expect(graph.nodes.filter(node => node.kind === 'unmatched')).toHaveLength(4)
  })
  it('does not count duplicate aggregate tuples or repeated inventory rows twice', () => {
    const graph = buildGraph(envelope([relation(), relation()]), [install(), install()], catalog, filters)
    expect(graph.edges).toHaveLength(2)
    expect(graph.representedObservations).toBe(4)
    expect(graph.representedInstallations).toBe(1)
  })
  it('makes deterministic positions and membership independent of response ordering', () => {
    const rows = [relation(), relation({ source_ip: '192.0.2.2' }), relation({ domain: 'unknown.test', catalog_match_id: null })]
    const a = buildGraph(envelope(rows), [install()], catalog, filters)
    const b = buildGraph(envelope([...rows].reverse()), [install()], catalog, filters)
    expect(a.nodes).toEqual(b.nodes)
    expect(a.edges).toEqual(b.edges)
    expect(new Set(a.nodes.map(node => node.position[2])).size).toBeGreaterThan(1)
  })
  it('enforces node and edge caps with honest eligible/omitted counts and retained endpoint pairs', () => {
    const rows = Array.from({ length: 500 }, (_, i) => relation({ source_ip: `source-${i}`, domain: `domain-${i}`, catalog_match_id: null }))
    const graph = buildGraph(envelope(rows), [], [], filters)
    expect(graph.nodes).toHaveLength(NODE_CAP)
    expect(graph.edges).toHaveLength(80)
    expect(graph.eligibleEdges).toBe(500)
    expect(graph.omittedEdges).toBe(420)
    expect(graph.omittedNodes).toBe(840)
    expect(graph.representedObservations).toBe(320)
    expect(graph.edges.every(edge => graph.nodes.some(node => node.id === edge.source) && graph.nodes.some(node => node.id === edge.target))).toBe(true)
    const dense = buildGraph(envelope(rows.map(row => ({ ...row, source_ip: 'one', catalog_match_id: 'catalog-1' }))), [], catalog, filters)
    expect(dense.edges).toHaveLength(EDGE_CAP)
    expect(dense.omittedEdges).toBe(180)
  })
  it('searches complete relationships and separates installation from network filters', () => {
    const graph = buildGraph(envelope([relation()]), [install()], catalog, { ...filters, kind: 'installation', search: 'Service', category: 'code_assistant' })
    expect(graph.edges).toHaveLength(1)
    expect(graph.edges[0].kind).toBe('installation')
    expect(graph.representedObservations).toBe(0)
    expect(buildGraph(envelope([relation()]), [], catalog, { ...filters, search: 'no match' }).edges).toHaveLength(0)
  })
  it('keeps every parallel relation control point within a bounded depth fan', () => {
    const offsets = Array.from({ length: EDGE_CAP }, (_, ordinal) => curveOffset(ordinal))
    expect(offsets.every(([y, z]) => Math.abs(y) <= 26 && Math.abs(z) <= 42)).toBe(true)
    expect(new Set(offsets.map(offset => offset.join(','))).size).toBe(EDGE_CAP)
  })
})
