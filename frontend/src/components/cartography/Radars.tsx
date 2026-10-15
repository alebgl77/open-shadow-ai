import { useId, useMemo, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { useI18n } from '@/i18n'
import type { MessageKey } from '@/i18n/messages'
import type { NetworkRelation, NetworkRelations } from '@/api/network'
import type { CatalogItem } from '@/types'
import { relationKey, type RadarChart, type RadarData, type RadarSelection } from './radar'
import './radar.css'

const FAMILY_LABELS: Record<string, MessageKey> = {
  conversation: 'Conversation / writing / search', code: 'Code / automation', media: 'Media / design',
  other: 'Other available categories', unavailable: 'Category unavailable', unassociated: 'No catalog association',
}
const TITLES: Record<RadarChart, MessageKey> = { protocols: 'Protocol distribution', families: 'Current catalog families' }
const point = (index: number, count: number, radius: number) => {
  const angle = -Math.PI / 2 + index * Math.PI * 2 / count
  return [160 + Math.cos(angle) * radius, 160 + Math.sin(angle) * radius]
}
const polygon = (count: number, radius: number) => Array.from({ length: count }, (_, index) => point(index, count, radius).join(',')).join(' ')

function RadarCard({ chart, data, selected, onSelect, loading }: { chart: RadarChart; data: RadarData; selected: RadarSelection | null; onSelect: (value: RadarSelection) => void; loading: boolean }) {
  const { tr, formatNumber } = useI18n()
  const id = useId()
  const label = (axis: string) => chart === 'protocols' ? axis : tr(FAMILY_LABELS[axis])
  const percent = (value: number) => formatNumber(value, { style: 'percent', maximumFractionDigits: 1 })
  const ready = data.state === 'ready'
  const title = tr(TITLES[chart])
  const message = loading ? tr('Loading radar evidence…') : data.reason === 'catalog' ? tr('Catalog families are unavailable until the current catalog loads successfully.') : data.reason === 'counts' ? tr('Radar data is unavailable because observation counts are invalid or exceed the safe numeric range.') : data.state === 'empty' ? tr('No loaded observations. Percentages are undefined when the denominator is zero.') : tr('Radar evidence is unavailable. No sample data has been substituted.')
  return <section className={`cart-radar-card cart-radar-${chart}`} aria-labelledby={`${id}-heading`}>
    <header><p className="eyebrow">{tr('Share of loaded observations')}</p><h2 id={`${id}-heading`}>{title}</h2><p>{tr(chart === 'protocols' ? 'Observed metadata protocols, weighted by observation count.' : 'Disjoint families from current raw catalog categories; no service-name inference.')}</p></header>
    <div className="cart-radar-body">
      <div className="cart-radar-plot">
        <svg viewBox="0 0 320 320" role="img" aria-labelledby={`${id}-title ${id}-description`}>
          <title id={`${id}-title`}>{title}</title><desc id={`${id}-description`}>{tr('Fixed 0–100% axes. Each value is its observation count divided by all loaded observations. Read or select the numbered axes in the list.')}</desc>
          {[.25, .5, .75, 1].map(ring => <polygon key={ring} points={polygon(data.axes.length, 112 * ring)} className="cart-radar-ring"/>)}
          {data.axes.map((axis, index) => <line key={axis.id} x1="160" y1="160" x2={point(index, data.axes.length, 112)[0]} y2={point(index, data.axes.length, 112)[1]} className="cart-radar-spoke"/>)}
          {[.25, .5, .75, 1].map(ring => <text key={ring} x="166" y={160 - 112 * ring + 4} className="cart-radar-scale">{percent(ring)}</text>)}
          <text x="166" y="174" className="cart-radar-scale">{percent(0)}</text>
          {ready && <polygon data-testid="radar-values" points={data.axes.map((axis, index) => point(index, data.axes.length, 112 * axis.share!).join(',')).join(' ')} className="cart-radar-values"/>}
          {data.axes.map((axis, index) => <g key={axis.id}>
            <circle cx={point(index, data.axes.length, 137)[0]} cy={point(index, data.axes.length, 137)[1]} r="12" className="cart-radar-axis-number"/>
            <text x={point(index, data.axes.length, 137)[0]} y={point(index, data.axes.length, 137)[1] + 4} textAnchor="middle" className="cart-radar-number">{formatNumber(index + 1)}</text>
            {ready && <circle cx={point(index, data.axes.length, 112 * axis.share!)[0]} cy={point(index, data.axes.length, 112 * axis.share!)[1]} r="3" className="cart-radar-dot"/>}
          </g>)}
        </svg>
      </div>
      <ol className="cart-radar-axes" aria-label={tr('{title} numeric values', { title })}>
        {data.axes.map((axis, index) => <li key={axis.id}><button type="button" disabled={data.state === 'unavailable'} aria-pressed={selected?.chart === chart && selected.id === axis.id} onClick={() => onSelect({ chart, id: axis.id })}>
          <span className="cart-radar-axis-label"><b aria-hidden="true">{formatNumber(index + 1)}</b>{label(axis.id)}</span>
          <span className="cart-radar-axis-value">{axis.observations == null ? '—' : formatNumber(axis.observations)} <small>{tr('observations')}</small><strong>{axis.share == null ? '—' : percent(axis.share)}</strong></span>
        </button></li>)}
      </ol>
    </div>
    {data.state !== 'unavailable' && <p className="cart-radar-denominator">{tr('Loaded denominator: {count} observations.', { count: formatNumber(data.denominator!) })}</p>}
    {!ready && <p className="cart-radar-state" role="status">{message}</p>}
  </section>
}

export default function Radars({ protocols, families, network, catalog, catalogCapped, networkLoading, catalogLoading, selected, onSelect, onClose, onInspect, focusedKey, detail }: {
  protocols: RadarData; families: RadarData; network: NetworkRelations | undefined; catalog: CatalogItem[] | undefined; catalogCapped: boolean
  networkLoading: boolean; catalogLoading: boolean; selected: RadarSelection | null; onSelect: (value: RadarSelection) => void; onClose: () => void
  onInspect: (row: NetworkRelation, trigger: HTMLButtonElement) => void; focusedKey?: string; detail?: ReactNode
}) {
  const { tr, formatNumber } = useI18n()
  const names = useMemo(() => new Map(catalog?.map(item => [item.catalog_item_id, item])), [catalog])
  const axis = selected && (selected.chart === 'protocols' ? protocols : families).axes.find(value => value.id === selected.id)
  const axisLabel = selected && (selected.chart === 'protocols' ? selected.id : tr(FAMILY_LABELS[selected.id]))
  const coverage = protocols.denominator != null && Number.isSafeInteger(network?.total_observations) && network!.total_observations >= protocols.denominator
  return <section className="cart-radars" aria-label={tr('Loaded observation radars')}>
    <div className="cart-radar-grid">
      <RadarCard chart="protocols" data={protocols} selected={selected} onSelect={onSelect} loading={networkLoading}/>
      <RadarCard chart="families" data={families} selected={selected} onSelect={onSelect} loading={networkLoading || catalogLoading}/>
    </div>
    <div className="cart-radar-scope"><p>{tr('Radars use all unique loaded network relationships before graph filters and the 160-node / 320-relationship display caps. The observation window and protocol request apply to both charts.')}</p>
      {coverage && <p>{tr('Computed loaded observations: {represented}; full selected-window observations: {total}.', { represented: formatNumber(protocols.denominator!), total: formatNumber(network!.total_observations) })}</p>}
      <p>{tr('Loaded relationships can be a server-limited subset. Percentages describe this subset, not the full window or AI use. Polygon area is not a score.')}{' '}{network?.truncated && tr('Server relation limit reached.')}</p>
      <p>{tr('Families reflect the current loaded catalog, not historical actions. Missing catalog rows and empty categories are separate from no catalog association.')}</p>
      {catalogCapped && <p>{tr('Catalog labels cover at most 500 entries. Unloaded service IDs are shown verbatim.')}</p>}
    </div>
    {selected && axis && <section className="cart-radar-drilldown" aria-label={tr('Radar relationship drilldown')}>
      <header><div><p className="eyebrow">{tr('Loaded relationship evidence')}</p><h2>{axisLabel}</h2><p>{tr('{count} loaded relationships in this axis', { count: formatNumber(axis.rows.length) })}</p></div><button type="button" onClick={onClose} aria-label={tr('Close radar drilldown')}><X size={17}/></button></header>
      <div className={`cart-radar-evidence ${detail ? 'cart-radar-has-detail' : ''}`}>
        <div className="cart-radar-rows">{!axis.rows.length ? <p role="status">{tr('No loaded relationships belong to this axis. This does not establish an absence of activity.')}</p> : <ul aria-label={tr('Relationships in selected radar axis')}>{axis.rows.map(row => {
          const key = relationKey(row), category = row.catalog_match_id == null ? undefined : names.get(row.catalog_match_id)?.category
          return <li key={key}><div className="cart-radar-row-title"><span>{row.source_ip || tr('Source address not observed')} → {row.domain || tr('Hostname not observed')}</span><button type="button" aria-pressed={focusedKey === key} onClick={event => onInspect(row, event.currentTarget)}>{tr('Inspect relationship')}</button></div>
            <dl><div><dt>{tr('Protocol')}</dt><dd>{row.protocol}</dd></div><div><dt>{tr('Observations')}</dt><dd>{formatNumber(row.observations)}</dd></div><div><dt>{tr('Catalog item ID')}</dt><dd>{row.catalog_match_id == null ? tr('No catalog association') : row.catalog_match_id || tr('Not reported')}</dd></div><div><dt>{tr('Current raw category')}</dt><dd>{typeof category === 'string' && category.trim() ? category : tr('Not reported')}</dd></div></dl>
          </li>
        })}</ul>}</div>
        {detail}
      </div>
    </section>}
  </section>
}
