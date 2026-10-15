import { describe, expect, it } from 'vitest'
import type { NetworkRelation, NetworkRelations } from '@/api/network'
import type { CatalogItem } from '@/types'
import { buildGraph } from './model'
import { buildRadars, relationFamily, relationKey } from './radar'

const row = (values: Partial<NetworkRelation> = {}): NetworkRelation => ({ source_ip: '192.0.2.1', domain: 'service.test', catalog_match_id: 'known', protocol: 'TLS', observations: 1, first_seen: '', last_seen: '', ...values })
const envelope = (items: NetworkRelation[]): NetworkRelations => ({ items, hours: 24, protocol: null, total_relations: 800, represented_relations: items.length, total_observations: 5000, represented_observations: 999, truncated: true, limitations: [] })
const item = (id: string, category: string) => ({ catalog_item_id: id, category, canonical_name: 'A name must not affect grouping' }) as CatalogItem
const counts = (data: ReturnType<typeof buildRadars>['protocols']) => data.axes.map(axis => axis.observations)

describe('loaded observation radar aggregation', () => {
  it('weights protocols by observations rather than groups, includes QUIC and uses the computed loaded denominator', () => {
    const data = buildRadars(envelope([row({ protocol: 'DNS', observations: 80 }), row({ protocol: 'TLS', observations: 10 }), row({ protocol: 'TLS', domain: 'second.test', observations: 5 }), row({ protocol: 'QUIC', observations: 5 })]), [])
    expect(data.protocols.denominator).toBe(100)
    expect(data.protocols.axes.map(axis => axis.id)).toEqual(['DNS', 'TLS', 'QUIC', 'HTTP'])
    expect(counts(data.protocols)).toEqual([80, 15, 5, 0])
    expect(data.protocols.axes.map(axis => axis.share)).toEqual([.8, .15, .05, 0])
    expect(data.protocols.axes.reduce((sum, axis) => sum + axis.share!, 0)).toBeCloseTo(1)
  })
  it('deduplicates only exact tuples, retaining the first aggregate just like buildGraph', () => {
    const first = row({ source_ip: '', domain: '', catalog_match_id: null, observations: 7 })
    const items = [first, { ...first, observations: 99 }, { ...first, protocol: 'QUIC' as const }, { ...first, catalog_match_id: '' }, { ...first, source_ip: '192.0.2.2' }, { ...first, domain: 'different.test' }, { ...first, catalog_match_id: undefined } as unknown as NetworkRelation]
    const network = envelope(items), data = buildRadars(network, [])
    expect(data.protocols.denominator).toBe(35)
    expect(data.protocols.denominator).toBe(buildGraph(network, [], [], { kind: 'all', category: '', search: '' }).representedObservations)
    expect(data.protocols.axes.flatMap(axis => axis.rows)).toHaveLength(5)
    expect(data.protocols.axes[1].rows[0]).toBe(first)
    expect(relationKey(first)).not.toBe(relationKey({ ...first, catalog_match_id: '' }))
    expect(counts(data.families)).toEqual([0, 0, 0, 0, 7, 28])
  })
  it('partitions six families solely by current raw category, separating missing IDs from no association', () => {
    const catalog = [item('chat', 'llm_chat'), item('write', 'writing_assistant'), item('translate', 'translation_ai'), item('search', 'search_ai'), item('code', 'code_assistant'), item('agent', 'agent_automation'), item('image', 'image_gen'), item('voice', 'voice_ai'), item('video', 'video_ai'), item('design', 'design_ai'), item('demo', 'saas_app'), item('platform', 'ai_platform'), item('data', 'data_ai'), item('proto', '__proto__'), item('ctor', 'constructor'), item('future', 'future_category'), item('empty', ''), item('spaces', '   ')]
    const items = [...catalog.map(value => row({ catalog_match_id: value.catalog_item_id })), row({ catalog_match_id: 'not-loaded' }), row({ catalog_match_id: null }), row({ catalog_match_id: undefined } as unknown as Partial<NetworkRelation>)]
    const data = buildRadars(envelope(items), catalog)
    expect(counts(data.families)).toEqual([4, 2, 4, 6, 3, 1])
    expect(data.families.denominator).toBe(20)
    expect(data.families.axes.reduce((sum, axis) => sum + axis.observations!, 0)).toBe(data.protocols.denominator)
    expect(data.families.axes.reduce((sum, axis) => sum + axis.share!, 0)).toBeCloseTo(1)
    expect(relationFamily(row({ catalog_match_id: 'missing-brand-name-chatgpt' }), new Map())).toBe('unavailable')
    expect(relationFamily(row({ catalog_match_id: '__proto__' }), new Map())).toBe('unavailable')
  })
  it('allows an honest 100% Other family for the current demo taxonomy and never normalizes categories', () => {
    const data = buildRadars(envelope([row()]), [item('known', 'saas_app')])
    expect(data.families.axes[3].share).toBe(1)
    for (const category of ['LLM_CHAT', ' llm_chat', 'llm_chat ', 'toString']) expect(relationFamily(row(), new Map([['known', item('known', category)]]))).toBe('other')
  })
  it('keeps family data unavailable until catalog success but protocols remain valid', () => {
    const data = buildRadars(envelope([row()]), undefined)
    expect(data.protocols.state).toBe('ready')
    expect(data.families.state).toBe('unavailable')
    expect(data.families.reason).toBe('catalog')
    expect(data.families.axes.every(axis => axis.observations === null && axis.share === null)).toBe(true)
    expect(buildRadars(undefined, []).protocols.state).toBe('unavailable')
  })
  it.each([{ items: [] }, { items: [row({ observations: 0 })] }])('keeps a zero denominator undefined rather than fabricating a polygon or percentages', ({ items }) => {
    const data = buildRadars(envelope(items), [])
    expect(data.protocols.state).toBe('empty')
    expect(data.protocols.denominator).toBe(0)
    expect(data.protocols.axes.every(axis => axis.share === null && axis.observations === 0)).toBe(true)
  })
  it.each([-1, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, .5, '2', null, undefined])('rejects invalid observation counts: %s', observations => {
    const data = buildRadars(envelope([row({ observations: observations as number })]), [])
    expect(data.protocols.state).toBe('unavailable')
    expect(data.families.state).toBe('unavailable')
    expect(data.protocols.reason).toBe('counts')
    expect(data.protocols.denominator).toBeNull()
  })
  it('rejects overflow totals, unknown protocols and malformed duplicate counts instead of dropping them', () => {
    for (const items of [[row({ observations: Number.MAX_SAFE_INTEGER }), row({ domain: 'other.test' })], [row({ protocol: 'SMTP' as NetworkRelation['protocol'] })], [row(), row({ observations: NaN })]]) {
      expect(buildRadars(envelope(items), []).protocols.reason).toBe('counts')
    }
    expect(buildRadars(envelope([row({ observations: Number.MAX_SAFE_INTEGER })]), []).protocols.denominator).toBe(Number.MAX_SAFE_INTEGER)
  })
  it('uses all loaded unique relations irrespective of full totals, local graph filters and caps', () => {
    const items = Array.from({ length: 500 }, (_, i) => row({ domain: `domain-${i}.test`, observations: 2 }))
    const network = envelope(items), catalog = [item('known', 'code_assistant')]
    const data = buildRadars(network, catalog)
    expect(data.protocols.denominator).toBe(1000)
    expect(data.protocols.axes[1].rows).toHaveLength(500)
    expect(data.families.axes[1].observations).toBe(1000)
    expect(buildGraph(network, [], catalog, { kind: 'all', category: '', search: '' }).edges).toHaveLength(320)
    expect(buildGraph(network, [], catalog, { kind: 'installation', category: 'other', search: 'absent' }).edges).toHaveLength(0)
    expect(buildRadars(network, catalog)).toEqual(data)
  })
})
