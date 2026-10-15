import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { Link } from 'react-router-dom'
import { Box, ChevronLeft, Info, Network, Search, Shield, X } from 'lucide-react'
import { useI18n } from '@/i18n'
import { useAuthStore } from '@/stores/auth'
import { NETWORK_NOTICE, NETWORK_PROTOCOLS, getNetworkEvent, getNetworkEvents, networkEndpoint, type NetworkFilters, type NetworkProtocol, type NetworkRelation, type NetworkRelations } from '@/api/network'
import { buildGraph, neighbors, type Graph, type GraphNode, type Selection } from '@/components/cartography/model'
import { loadCatalog, loadCatalogItem, loadInventory, loadRelations } from '@/components/cartography/data'
import Radars from '@/components/cartography/Radars'
import { buildRadars, relationKey, type RadarSelection } from '@/components/cartography/radar'
import ErrorAlert from '@/components/ui/ErrorAlert'
import type { MessageKey } from '@/i18n/messages'
import '@/components/cartography/cartography.css'

const Scene = lazy(() => import('@/components/cartography/Scene'))
const PAGE_SIZE = 20
const statusOf = (error: unknown) => isAxiosError(error) ? error.response?.status : undefined
const INSTALL_LABELS: Record<string, MessageKey> = { store: 'Store', user: 'User-installed', unpacked: 'Unpacked', external: 'External installer', policy: 'Policy', component: 'Browser component', orphan: 'Orphan', unknown: 'Unknown source', '': 'Source not reported' }
type RadarOrigin = { axis: RadarSelection; network: NetworkRelations; revision: number; hours: number; protocol: NetworkProtocol | undefined; catalogRevision: number }
type RadarFocus = { row: NetworkRelation; selection: NonNullable<Selection>; trigger: HTMLButtonElement }

export default function Cartography() {
  const { mode, session, user, isAuthenticated, cartographyDeniedSession } = useAuthStore()
  const { tr } = useI18n()
  if (!isAuthenticated || (user?.role !== 'admin' && user?.role !== 'analyst')) return <div role="alert" className="stat-card flex items-start gap-3"><Shield size={20}/><p>{tr('Network access requires an analyst or administrator role.')}</p></div>
  if (cartographyDeniedSession === session) return <section role="alert" className="stat-card"><Shield className="text-amber-300 mb-3"/><h1 className="page-heading">{tr('Cartography access denied')}</h1><p className="page-description">{tr('Your permissions changed. Cartography data has been cleared. Sign in again to continue.')}</p></section>
  return <CartographyWorkspace key={`${mode}:${session}:${user.role}`} scope={[mode, session, user.role]} />
}

function CartographyWorkspace({ scope }: { scope: readonly [string, number, string] }) {
  const { tr, textLabel, enumLabel, formatNumber } = useI18n()
  const queries = useQueryClient()
  const [hours, setHours] = useState(24), [protocol, setProtocol] = useState<NetworkProtocol | undefined>()
  const [kind, setKind] = useState<'all' | 'network' | 'installation'>('all'), [category, setCategory] = useState(''), [search, setSearch] = useState('')
  const [view, setView] = useState<'3d' | '2d'>('3d'), [unavailable, setUnavailable] = useState(false)
  const [selection, setSelection] = useState<Selection>(null), [closed, setClosed] = useState(false), [denied, setDenied] = useState(false)
  const [radarOrigin, setRadarOrigin] = useState<RadarOrigin | null>(null), [radarFocus, setRadarFocus] = useState<RadarFocus | null>(null)
  const deniedRef = useRef(false), mounted = useRef(true)
  const prefix = useMemo(() => ['cartography', ...scope], [scope[0], scope[1], scope[2]]) // Session identity is deliberately part of every key.
  const guard = useCallback(async <T,>(read: () => Promise<T>): Promise<T> => {
    try {
      const result = await read()
      const auth = useAuthStore.getState()
      if (!mounted.current || deniedRef.current || auth.cartographyDeniedSession === scope[1] || auth.mode !== scope[0] || auth.session !== scope[1] || auth.user?.role !== scope[2] || !auth.isAuthenticated) throw new DOMException('Aborted', 'AbortError')
      return result
    } catch (error) {
      if ([401, 403].includes(statusOf(error) || 0) && mounted.current) { deniedRef.current = true; useAuthStore.getState().denyCartography(scope[1]); setDenied(true) }
      throw error
    }
  }, [scope[0], scope[1], scope[2]])
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; void queries.cancelQueries({ queryKey: prefix }); queries.removeQueries({ queryKey: prefix }) }
  }, [queries, prefix])
  useEffect(() => {
    if (!denied) return
    setSelection(null); setRadarOrigin(null); setRadarFocus(null); void queries.cancelQueries({ queryKey: prefix }).then(() => queries.removeQueries({ queryKey: prefix }))
  }, [denied, queries, prefix])
  const network = useQuery({ queryKey: [...prefix, 'relations', hours, protocol], queryFn: ({ signal }) => guard(() => loadRelations(hours, protocol, signal)), enabled: !denied, retry: false })
  const inventory = useQuery({ queryKey: [...prefix, 'inventory'], queryFn: ({ signal }) => guard(() => loadInventory(signal)), enabled: !denied, retry: false })
  const catalog = useQuery({ queryKey: [...prefix, 'catalog'], queryFn: ({ signal }) => guard(() => loadCatalog(signal)), enabled: !denied, retry: false })
  const networkRevision = queries.getQueryState([...prefix, 'relations', hours, protocol])?.dataUpdateCount || 0
  const catalogRevision = queries.getQueryState([...prefix, 'catalog'])?.dataUpdateCount || 0
  const radars = useMemo(() => buildRadars(network.isError || denied ? undefined : network.data, catalog.isSuccess && !denied ? catalog.data.items : undefined), [network.data, network.isError, catalog.data, catalog.isSuccess, denied])
  // Bind radar-origin evidence to this successful payload; refetch/error/new query invalidates it synchronously.
  const radarAxis = radarOrigin && !denied && !network.isError && !network.isFetching && radarOrigin.network === network.data && radarOrigin.revision === networkRevision && radarOrigin.hours === hours && radarOrigin.protocol === protocol &&
    (radarOrigin.axis.chart === 'protocols' || (catalog.isSuccess && !catalog.isFetching && radarOrigin.catalogRevision === catalogRevision)) ? radarOrigin.axis : null
  const focusedGraph = useMemo(() => radarAxis && radarFocus && network.data ? buildGraph({ ...network.data, items: [radarFocus.row] }, [], catalog.isSuccess ? catalog.data.items : [], { kind: 'all', category: '', search: '' }) : null, [radarAxis, radarFocus, network.data, catalog.data, catalog.isSuccess])
  const graph = useMemo(() => buildGraph(network.isError || denied ? undefined : network.data, inventory.isError || denied ? [] : inventory.data?.items || [], catalog.isError || denied ? [] : catalog.data?.items || [], { kind, category, search }), [network.data, network.isError, inventory.data, inventory.isError, catalog.data, catalog.isError, kind, category, search, denied])
  const nodeLabel = useCallback((node: GraphNode) => node.label || (node.kind === 'ip' ? tr('Source address not observed') : node.kind === 'host' ? tr('Host label not reported') : tr('Hostname not observed')), [tr])
  const labels = useMemo(() => new Map(graph.nodes.map(node => [node.id, nodeLabel(node)])), [graph, nodeLabel])
  const focusedLabels = useMemo(() => new Map(focusedGraph?.nodes.map(node => [node.id, nodeLabel(node)])), [focusedGraph, nodeLabel])
  const choose = (value: Selection) => { setRadarOrigin(null); setRadarFocus(null); setClosed(false); setSelection(value) }
  const resetSelection = () => { setSelection(null); setClosed(false) }
  const closeRadar = () => { setRadarOrigin(null); setRadarFocus(null) }
  const chooseAxis = (axis: RadarSelection) => {
    if (!network.data || network.isError || network.isFetching || denied) return
    setSelection(null); setClosed(true); setRadarFocus(null)
    setRadarOrigin({ axis, network: network.data, revision: networkRevision, hours, protocol, catalogRevision })
  }
  const inspectRadar = (row: NetworkRelation, trigger: HTMLButtonElement) => {
    if (!radarAxis) return
    const isolated = buildGraph({ ...network.data!, items: [row] }, [], catalog.isSuccess ? catalog.data.items : [], { kind: 'all', category: '', search: '' })
    if (isolated.edges[0]) setRadarFocus({ row, selection: { kind: 'edge', id: isolated.edges[0].id }, trigger })
  }
  const closeRadarFocus = () => {
    setRadarFocus(null)
    const auth = useAuthStore.getState(), current = queries.getQueryState([...prefix, 'relations', hours, protocol])
    const currentCatalog = queries.getQueryState([...prefix, 'catalog'])
    if (radarOrigin && radarAxis && radarFocus?.trigger.isConnected && !deniedRef.current && auth.cartographyDeniedSession !== scope[1] && auth.isAuthenticated && auth.mode === scope[0] && auth.session === scope[1] && auth.user?.role === scope[2] &&
      current?.status === 'success' && current.fetchStatus !== 'fetching' && current.dataUpdateCount === radarOrigin.revision &&
      (radarAxis.chart === 'protocols' || (currentCatalog?.status === 'success' && currentCatalog.fetchStatus !== 'fetching' && currentCatalog.dataUpdateCount === radarOrigin.catalogRevision))) radarFocus.trigger.focus()
  }
  useEffect(() => { if (radarOrigin && !radarAxis) { setRadarOrigin(null); setRadarFocus(null) } }, [radarOrigin, radarAxis])
  useEffect(() => {
    if (denied || closed || radarAxis) return
    const exists = selection?.kind === 'node' ? graph.nodes.some(node => node.id === selection.id) : graph.edges.some(edge => edge.id === selection?.id)
    if (!exists) setSelection(graph.edges.length ? { kind: 'edge', id: graph.edges[0].id } : null)
  }, [graph, selection, closed, denied, radarAxis])
  const categories = [...new Set(catalog.data?.items.map(item => item.category) || [])].sort()
  const onUnavailable = useCallback(() => { setUnavailable(true); setView('2d') }, [])
  const pending = network.isPending || inventory.isPending
  if (denied) return <section role="alert" className="stat-card"><Shield className="text-amber-300 mb-3"/><h1 className="page-heading">{tr('Cartography access denied')}</h1><p className="page-description">{tr('Your permissions changed. Cartography data has been cleared. Sign in again to continue.')}</p></section>
  return <div className="cartography">
    <header className="cart-heading"><div><p className="eyebrow">{tr('Evidence topology')}</p><h1 className="page-heading">{tr('AI cartography')}</h1><p className="page-description">{tr('Explore observed connections and reported installations. Follow each relationship back to its evidence.')}</p></div><div className="cart-mode" role="group" aria-label={tr('Cartography display')}><button aria-pressed={view === '3d'} onClick={() => { setUnavailable(false); setView('3d') }}><Box size={15}/>3D</button><button aria-pressed={view === '2d'} onClick={() => setView('2d')}><Network size={15}/>{tr('List view')}</button></div></header>
    <div className="cart-toolbar">
      <label>{tr('Observation window')}<select className="field" value={hours} onChange={event => { setHours(Number(event.target.value)); closeRadar(); resetSelection() }}>{[24, 168].map(value => <option key={value} value={value}>{tr('Last {hours} hours', { hours: formatNumber(value) })}</option>)}</select></label>
      <label>{tr('Protocol')}<select className="field" value={protocol || ''} onChange={event => { setProtocol(event.target.value as NetworkProtocol || undefined); closeRadar(); resetSelection() }}><option value="">{tr('All protocols')}</option>{NETWORK_PROTOCOLS.map(value => <option key={value}>{value}</option>)}</select></label>
      <label>{tr('Relationship type')}<select className="field" value={kind} onChange={event => { setKind(event.target.value as typeof kind); resetSelection() }}><option value="all">{tr('All relationships')}</option><option value="network">{tr('Network observation')}</option><option value="installation">{tr('Reported installation')}</option></select></label>
      <label>{tr('Category')}<select className="field" value={category} onChange={event => { setCategory(event.target.value); resetSelection() }}><option value="">{tr('All categories')}</option>{categories.map(value => <option key={value} value={value}>{enumLabel(value)}</option>)}</select></label>
      <label className="cart-search">{tr('Search the graph')}<span><Search size={15}/><input className="field" type="search" value={search} onChange={event => { setSearch(event.target.value); resetSelection() }} placeholder={tr('IP, host label, service or hostname')} /></span></label>
    </div>
    <div className="cart-summary" aria-label={tr('Cartography coverage')}><span><strong>{network.isError ? '—' : formatNumber(network.data?.total_observations || 0)}</strong>{tr('Network observations in window')}</span><span><strong>{inventory.isError ? '—' : formatNumber(inventory.data?.total || 0)}</strong>{tr('Retained installations')}</span><span><strong>{formatNumber(graph.nodes.length)} / {formatNumber(graph.edges.length)}</strong>{tr('Visible nodes / relationships')}</span></div>
    {scope[0] === 'demo' && <p className="cart-note" role="status">{tr('Synthetic network observations · fictional sensors and documentation-only IP addresses.')}</p>}
    {network.isError && <ErrorAlert message={tr('Network observations are unavailable. No sample data has been substituted.')} onRetry={() => void network.refetch()}/>}
    {inventory.isError && <ErrorAlert message={tr('The extension inventory is unavailable. No sample data has been substituted.')} onRetry={() => void inventory.refetch()}/>}
    {catalog.isError && <p role="status" className="cart-note">{tr('Service labels are unavailable. Observed hostnames are still shown.')}</p>}
    {unavailable && <p className="cart-note" role="status">{tr('3D is unavailable on this device. All relationships and evidence remain available in the list.')}</p>}
    <div className={`cart-workspace ${selection ? 'cart-has-detail' : ''}`}>
      <section className="cart-visual" aria-label={tr('Cartography graph')}>
        <div className="cart-visual-top"><span className="eyebrow">{tr('Observed relationships')}</span><span>{tr('{count} represented observations', { count: formatNumber(graph.representedObservations) })} · {tr('{count} represented installations', { count: formatNumber(graph.representedInstallations) })}</span></div>
        {pending && <p className="cart-loading" role="status">{tr('Loading cartography…')}</p>}
        {!pending && !graph.edges.length ? <div className="cart-empty"><Network size={34}/><h2>{tr('No relationships in this selection')}</h2><p>{tr('An empty result does not establish the absence of network activity or AI use.')}</p></div> : view === '3d' ? <Suspense fallback={<p className="cart-loading" role="status">{tr('Loading 3D scene…')}</p>}><Scene graph={graph} selection={selection} onSelect={choose} onUnavailable={onUnavailable} labels={labels}/></Suspense> : <div className="cart-table-scroll"><table className="cart-table"><caption className="sr-only">{tr('Observed relationships')}</caption><thead><tr><th>{tr('Source')}</th><th>{tr('AI tool / service')}</th><th>{tr('Evidence type')}</th><th>{tr('Trace')}</th></tr></thead><tbody>{graph.edges.map(edge => <tr key={edge.id}><td><button onClick={() => choose({ kind: 'node', id: edge.source })}>{labels.get(edge.source)}</button><small>{tr(graph.nodes.find(node => node.id === edge.source)?.kind === 'host' ? 'Reported host label' : 'Source address')}</small></td><td><button onClick={() => choose({ kind: 'node', id: edge.target })}>{labels.get(edge.target)}</button></td><td>{tr(edge.kind === 'network' ? 'Network observation' : 'Reported installation')}{edge.network && <small>{edge.network.protocol} · {formatNumber(edge.network.observations)}</small>}</td><td><button onClick={() => choose({ kind: 'edge', id: edge.id })}>{tr('Inspect relationship')}</button></td></tr>)}</tbody></table></div>}
        <ul className="cart-legend" aria-label={tr('Graph legend')}>{(['ip', 'host', 'service', 'unmatched'] as const).map(type => <li key={type}><i data-kind={type}/>{tr(type === 'ip' ? 'Source IP' : type === 'host' ? 'Reported host label' : type === 'service' ? 'Catalog service' : 'Unidentified host / extension')}</li>)}</ul>
      </section>
      {selection && <Detail key={`${selection.kind}:${selection.id}:${hours}:${protocol || ''}`} graph={graph} selection={selection} labels={labels} hours={hours} prefix={prefix} guard={guard} choose={choose} close={() => { setSelection(null); setClosed(true) }} />}
    </div>
    <Radars protocols={radars.protocols} families={radars.families} network={network.isError ? undefined : network.data} catalog={catalog.isSuccess ? catalog.data.items : undefined} catalogCapped={!!catalog.data?.capped} networkLoading={network.isPending} catalogLoading={catalog.isPending} selected={radarAxis} onSelect={chooseAxis} onClose={closeRadar} onInspect={inspectRadar} focusedKey={radarAxis && radarFocus ? relationKey(radarFocus.row) : undefined}
      detail={radarAxis && radarFocus && focusedGraph && <Detail key={`radar:${relationKey(radarFocus.row)}:${radarFocus.selection.kind}:${radarFocus.selection.id}:${hours}:${protocol || ''}`} graph={focusedGraph} selection={radarFocus.selection} labels={focusedLabels} hours={hours} prefix={prefix} guard={guard} isolated choose={value => { if (value) setRadarFocus({ ...radarFocus, selection: value }) }} close={closeRadarFocus} />}/>
    {graph.omittedEdges > 0 && <p className="cart-note" role="status">{tr('Graph display is bounded to 160 nodes and 320 relationships.')} {tr('{count} loaded relationships omitted from the graph', { count: formatNumber(graph.omittedEdges) })}</p>}
    {(network.data?.truncated || inventory.data?.truncated) && <p className="cart-note" role="status">{network.data?.truncated && tr('Server relation limit reached.')}{' '}{inventory.data?.truncated && tr('Inventory page limit reached.')}{' '}{tr('Search, category and relationship filters apply to loaded evidence. Change the window or protocol to request another network selection.')}{' '}<Link to={`/network?hours=${hours}${protocol ? `&protocol=${protocol}` : ''}`} className="text-accent">{tr('Open network observations')}</Link>{' · '}<Link to="/extensions?view=inventory" className="text-accent">{tr('Open the complete inventory')}</Link></p>}
    <p className="cart-note">{network.data && !network.isError && tr('Server returned {represented} of {total} network relationships.', { represented: formatNumber(network.data.represented_relations), total: formatNumber(network.data.total_relations) })}{' '}{inventory.data && !inventory.isError && tr('Loaded {represented} of {total} retained installations.', { represented: formatNumber(inventory.data.items.length), total: formatNumber(inventory.data.total) })}{' '}{tr('Visible source groups: {ips} IP labels and {hosts} reported host labels.', { ips: formatNumber(graph.nodes.filter(node => node.kind === 'ip').length), hosts: formatNumber(graph.nodes.filter(node => node.kind === 'host').length) })}</p>
    <details className="cart-disclosure"><summary><Info size={14}/>{tr('Coverage and interpretation')}</summary><div><p>{textLabel(NETWORK_NOTICE)}</p><p>{tr('Host labels are grouped within each collector. They are not guaranteed to represent unique physical devices, and they are never joined to source IPs.')}</p><p>{tr('Installation is presence evidence, not usage. Inventory covers retained endpoint reports, independently of the network observation window.')}</p><p>{tr('A source file or log line is not retained by this API. Models, people, prompts and risk are unknown here.')}</p><p>{tr('Graph shows {observations} of {totalObservations} network observations and {installations} of {totalInstallations} retained installations.', { observations: formatNumber(graph.representedObservations), totalObservations: network.isError ? '—' : formatNumber(network.data?.total_observations || 0), installations: formatNumber(graph.representedInstallations), totalInstallations: inventory.isError ? '—' : formatNumber(inventory.data?.total || 0) })}</p>{inventory.data?.identity && <p>{tr('Identity retention: {days} days', { days: formatNumber(inventory.data.identity.days) })}</p>}{catalog.data?.capped && <p>{tr('Catalog labels cover at most 500 entries. Unloaded service IDs are shown verbatim.')}</p>}<ul>{network.data?.limitations.map((limitation, index) => <li key={index}>{textLabel(limitation)}</li>)}</ul></div></details>
    <details className="cart-accessible"><summary>{tr('Select a node with the keyboard')}</summary><ul>{graph.nodes.map(node => <li key={node.id}><button aria-pressed={selection?.kind === 'node' && selection.id === node.id} onClick={() => choose({ kind: 'node', id: node.id })}><i data-kind={node.kind}/>{labels.get(node.id)}<small>{tr(node.kind === 'ip' ? 'Source IP' : node.kind === 'host' ? 'Reported host label' : node.kind === 'service' ? 'Catalog service' : 'Unidentified host / extension')}</small></button></li>)}</ul></details>
  </div>
}

type Guard = <T>(read: () => Promise<T>) => Promise<T>
function Detail({ graph, selection, labels, hours, prefix, guard, choose, close, isolated = false }: { graph: Graph; selection: NonNullable<Selection>; labels: Map<string, string>; hours: number; prefix: unknown[]; guard: Guard; choose: (value: Selection) => void; close: () => void; isolated?: boolean }) {
  const { tr, formatDate, formatNumber } = useI18n()
  const panel = useRef<HTMLElement>(null)
  const [page, setPage] = useState(1), [eventId, setEventId] = useState<string | null>(null)
  const node = selection.kind === 'node' ? graph.nodes.find(item => item.id === selection.id) : undefined
  const edge = selection.kind === 'edge' ? graph.edges.find(item => item.id === selection.id) : undefined
  const relations = neighbors(graph, selection)
  const filters: NetworkFilters = { hours, page, page_size: PAGE_SIZE }
  if (edge?.network) Object.assign(filters, { source_ip: edge.network.source_ip, domain: edge.network.domain, catalog_match_id: edge.network.catalog_match_id || '', protocol: edge.network.protocol })
  else if (node?.kind === 'ip') filters.source_ip = node.value
  else if (node?.catalogId) filters.catalog_match_id = node.catalogId
  // Node exploration is broader than a relation: all protocols for this source or catalog ID.
  const hasEvents = !!edge?.network || node?.kind === 'ip' || !!node?.catalogId
  const events = useQuery({ queryKey: [...prefix, 'events', filters], queryFn: ({ signal }) => guard(() => getNetworkEvents(filters, signal)), enabled: hasEvents, retry: false })
  const event = useQuery({ queryKey: [...prefix, 'event', hours, eventId], queryFn: ({ signal }) => guard(() => getNetworkEvent(eventId!, hours, signal)), enabled: !!eventId, retry: false })
  const catalogId = node?.catalogId || (edge ? graph.nodes.find(item => item.id === edge.target)?.catalogId : undefined)
  const item = useQuery({ queryKey: [...prefix, 'catalog-item', catalogId], queryFn: ({ signal }) => guard(() => loadCatalogItem(catalogId!, signal)), enabled: !!catalogId, retry: false })
  const installs = edge?.installations || (node?.kind === 'host' || node?.kind === 'service' ? relations.flatMap(relation => relation.installations) : [])
  const title = eventId ? tr('Event provenance') : node ? labels.get(node.id) : edge ? `${labels.get(edge.source)} → ${labels.get(edge.target)}` : tr('Relationship')
  const time = (value: string | null | undefined) => value ? formatDate(value) : tr('Not reported')
  const installSource = (value: string) => Object.hasOwn(INSTALL_LABELS, value) ? tr(INSTALL_LABELS[value]) : value
  const facts = (values: Array<[string, string | number]>) => <dl className="cart-facts">{values.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
  useEffect(() => { const escape = (e: KeyboardEvent) => { if (e.key === 'Escape') { if (eventId) setEventId(null); else close() } }; window.addEventListener('keydown', escape); return () => window.removeEventListener('keydown', escape) }, [eventId, close])
  useEffect(() => { if (isolated) panel.current?.focus() }, [isolated])
  return <aside ref={panel} tabIndex={isolated ? -1 : undefined} className="cart-detail" aria-label={tr('Evidence detail')}>
    <div className="cart-detail-top"><span className="eyebrow">{tr('Evidence detail')}</span><button aria-label={tr('Close evidence detail')} onClick={close}><X size={17}/></button></div>
    <nav className="cart-breadcrumb" aria-label={tr('Evidence navigation')}>{eventId ? <button onClick={() => setEventId(null)}><ChevronLeft size={13}/>{tr('Back to relationship')}</button> : edge ? <button onClick={() => choose({ kind: 'node', id: edge.source })}><ChevronLeft size={13}/>{tr('Back to source')}</button> : <span>{tr('Selected node')}</span>}</nav>
    <h2>{title}</h2>
    {isolated && <p className="cart-note cart-radar-isolated">{tr('Isolated relation from radar. Connected relationships here cover only this one loaded relation; source and service event inspection can cover all protocols in the selected window.')}</p>}
    {!eventId && <>
      <p className="cart-detail-kind">{tr(edge ? edge.kind === 'network' ? 'Network observation' : 'Reported installation' : node?.kind === 'ip' ? 'Source IP' : node?.kind === 'host' ? 'Reported host label' : node?.kind === 'service' ? 'Catalog service' : 'Unidentified host / extension')}</p>
      {node?.kind === 'host' && <><p className="cart-note">{tr('This is a reported label scoped to its collector, not a verified device identity.')}</p>{facts([[tr('Collector ID'), node.collector || tr('Not reported')]])}</>}
      {edge?.network && facts([[tr('Protocol'), edge.network.protocol], [tr('Observed hostname'), edge.network.domain || tr('Hostname not observed')], [tr('Observations'), formatNumber(edge.network.observations)], [tr('First seen'), time(edge.network.first_seen)], [tr('Last seen'), time(edge.network.last_seen)]])}
      {catalogId && <section className="cart-detail-section"><h3>{tr('Catalog association')}</h3>{facts([[tr('Catalog item ID'), catalogId], [tr('Current catalog name'), item.data?.canonical_name || tr('Not reported')]])}<p className="cart-note">{tr('The current catalog describes the service. Historical matching is explained only by metadata retained with the event.')}</p></section>}
      {node && <section className="cart-detail-section"><h3>{tr('Connected relationships')}</h3><ul className="cart-relations">{relations.map(relation => <li key={relation.id}><button onClick={() => choose({ kind: 'edge', id: relation.id })}><span>{labels.get(relation.source === node.id ? relation.target : relation.source)}</span><small>{relation.network ? `${relation.network.protocol} · ${formatNumber(relation.network.observations)}` : `${tr('Reported installation')} · ${formatNumber(relation.installations.length)}`}</small></button></li>)}</ul></section>}
      {edge && <div className="cart-endpoints"><button onClick={() => choose({ kind: 'node', id: edge.source })}>{tr('Explore source')}</button><button onClick={() => choose({ kind: 'node', id: edge.target })}>{tr('Explore service')}</button></div>}
      {installs.length > 0 && <section className="cart-detail-section"><h3>{tr('Reported installations')}</h3><p className="cart-note">{tr('Installation is presence evidence, not usage.')}</p><ul className="cart-installations">{installs.map(installation => <li key={installation.inventory_key}><strong>{installation.extension_name || tr('Unnamed extension')}</strong>{facts([[tr('Host'), installation.host_label || tr('Host label not reported')], [tr('Collector ID'), installation.collector_id], [tr('Browser'), installation.browser], [tr('Profile'), installation.profile || tr('Not reported')], [tr('Extension ID'), installation.extension_id], [tr('Version'), installation.version || tr('Not reported')], [tr('Enabled'), installation.enabled === null ? tr('State not reported') : tr(installation.enabled ? 'Enabled' : 'Disabled')], [tr('Install source'), installSource(installation.install_source)], [tr('Latest snapshot'), tr(installation.present_in_latest_snapshot ? 'Present' : 'Not present')], [tr('First seen'), time(installation.first_seen_at)], [tr('Last seen'), time(installation.last_seen_at)], [tr('Last event ID'), installation.last_event_id]])}{installation.detection_id && <Link to={`/discoveries/${encodeURIComponent(installation.detection_id)}`}>{tr('Open discovery evidence')}</Link>}<p className="cart-note">{tr('Source file and log line: not retained / not provided.')}</p></li>)}</ul></section>}
      {hasEvents && <section className="cart-detail-section"><h3>{tr('Observation evidence')}</h3><p className="cart-note">{tr(edge?.network ? 'Events match this exact source, hostname, catalog association and protocol.' : 'Events cover this source address or catalog service across all protocols in the selected window.')}</p>{events.isPending ? <p role="status">{tr('Loading network observations…')}</p> : events.isError ? <p role="alert">{tr('Network observations are unavailable. No sample data has been substituted.')}</p> : <><ul className="cart-event-list">{events.data?.items.map(observation => <li key={observation.event_id}><button onClick={() => setEventId(observation.event_id)}><span>{observation.protocol} · {time(observation.timestamp)}</span><small>{observation.event_id}</small></button></li>)}</ul>{!events.data?.items.length && <p>{tr('No observations on this page')}</p>}<div className="cart-pagination"><button disabled={page <= 1} onClick={() => setPage(value => value - 1)}>{tr('Previous')}</button><span>{tr('Page {page}', { page: formatNumber(page) })} · {formatNumber(events.data?.total || 0)}</span><button disabled={page * PAGE_SIZE >= (events.data?.total || 0)} onClick={() => setPage(value => value + 1)}>{tr('Next')}</button></div></>}</section>}
      <p className="cart-note">{tr('Model and risk: unknown. Observation volume does not establish usage or confidence.')}</p>
    </>}
    {eventId && <>{event.isPending ? <p role="status">{tr('Loading event provenance…')}</p> : event.isError ? <p role="alert">{tr(statusOf(event.error) === 404 ? 'This event is no longer available in the selected window, or the ID is unknown.' : 'Event provenance is unavailable. Try again later.')}</p> : event.data && <>{facts([[tr('Event ID'), event.data.event_id], [tr('Observed at'), time(event.data.timestamp)], [tr('Protocol'), event.data.protocol], [tr('Collector ID'), event.data.collector_id], [tr('Parser version'), event.data.parser_version || tr('Not reported')], [tr('Observed hostname'), event.data.domain || event.data.sni || event.data.url_host || tr('Hostname not observed')], [tr('Source address'), networkEndpoint(event.data.src_ip, undefined, tr('Not observed'))], [tr('Destination'), networkEndpoint(event.data.dst_ip, event.data.dst_port, tr('Not observed'))], [tr('SNI'), event.data.sni || tr('Not observed')], [tr('HTTP host'), event.data.url_host || tr('Not observed')], [tr('Catalog item ID'), event.data.catalog_match_id || tr('No catalog match')], [tr('Stored matching field'), event.data.match_field || tr('Not retained')], [tr('Stored association score'), event.data.match_confidence == null ? tr('Not retained') : formatNumber(event.data.match_confidence, { maximumFractionDigits: 3 })]])}<p className="cart-note">{tr('Stored field and score explain a reported catalog association; they do not establish AI use, a model or a person.')}</p><p className="cart-note">{tr('Source file and log line: not retained / not provided.')}</p><p className="cart-note">{tr('Parser version identifies the reported parser, not a retained source log.')}</p></>}</>}
  </aside>
}
