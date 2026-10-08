import { useI18n } from '@/i18n'
import { useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { Activity, Info, Network as NetworkIcon, Shield } from 'lucide-react'
import { Link, useSearchParams } from 'react-router-dom'
import { listCatalog } from '@/api/catalog'
import { getNetworkEvents, getNetworkOverview, NETWORK_NOTICE, NETWORK_PROTOCOLS, networkEndpoint, type NetworkProtocol } from '@/api/network'
import EmptyState from '@/components/ui/EmptyState'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { CardsSkeleton, TableSkeleton } from '@/components/ui/LoadingSkeleton'
import SourceIcons from '@/components/ui/SourceIcons'
import { useAuthStore } from '@/stores/auth'

const WINDOWS = [24, 72, 168]
const PAGE_SIZE = 20
const forbidden = (error: unknown) => isAxiosError(error) && error.response?.status === 403


export default function Network() {
  const { tr, textLabel, enumLabel, formatDate, formatNumber } = useI18n()

  const timeLabel = (value: string | null) => value && Number.isFinite(Date.parse(value)) ? formatDate(value) : tr('Not observed')
  const [params, setParams] = useSearchParams()
  const mode = useAuthStore(state => state.mode)
  const session = useAuthStore(state => state.session)
  const role = useAuthStore(state => state.user?.role)
  const canRead = role === 'admin' || role === 'analyst'
  const hours = WINDOWS.includes(Number(params.get('hours'))) ? Number(params.get('hours')) : 24
  const protocol = NETWORK_PROTOCOLS.includes(params.get('protocol') as NetworkProtocol) ? params.get('protocol') as NetworkProtocol : undefined
  const requestedPage = Number(params.get('page'))
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1
  const filters = { hours, protocol, page, page_size: PAGE_SIZE }

  const overview = useQuery({
    queryKey: ['network-overview', mode, session, hours],
    queryFn: ({ signal }) => getNetworkOverview(hours, signal), enabled: canRead, retry: false,
  })
  const events = useQuery({
    queryKey: ['network-events', mode, session, filters],
    queryFn: ({ signal }) => getNetworkEvents(filters, signal), enabled: canRead, retry: false,
  })
  const catalog = useQuery({
    queryKey: ['network-catalog', mode, session],
    queryFn: () => listCatalog({ page_size: 500 }), enabled: canRead, retry: false,
  })
  const catalogById = new Map((catalog.isError ? [] : catalog.data || []).map(item => [item.catalog_item_id, item]))
  const changeFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    if (key !== 'page') next.set('page', '1')
    setParams(next)
  }
  const permissionDenied = !canRead || forbidden(overview.error) || forbidden(events.error)
  const counts = overview.isError ? undefined : overview.data
  const rows = events.isError ? undefined : events.data
  const pages = Math.max(1, Math.ceil((rows?.total || 0) / PAGE_SIZE))

  return <div className="space-y-6">
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div><p className="eyebrow mb-2">{tr("Passive metadata")}</p><h1 className="page-heading">{tr("Network observations")}</h1><p className="page-description">{tr("Imported DNS, TLS, QUIC and HTTP observations from your network sensors.")}</p></div>
      <SourceIcons sources={['network']} />
    </div>
    {permissionDenied ? <section role="alert" className="stat-card flex gap-3 items-start"><Shield size={20} className="text-amber-300 shrink-0" /><div><h2 className="text-sm font-medium">{tr("Network access requires an analyst or administrator role.")}</h2><p className="text-xs text-slate-400 mt-2">{tr("Your current permissions do not allow access to network addresses and sensor observations.")}</p></div></section> : <>
      {mode === 'demo' && <p role="status" className="text-xs text-amber-200">{tr("Synthetic network observations · fictional sensors and documentation-only IP addresses.")}</p>}
      <div className="flex gap-3 rounded-xl border border-accent/20 bg-accent/5 p-4 text-xs text-slate-300 leading-relaxed"><Info size={16} className="text-accent shrink-0" /><p>{textLabel(NETWORK_NOTICE)}{' '}{tr("Counts represent imported observations deduplicated by event ID, not all traffic or requests. Repeated observations do not increase confidence.")}</p></div>
      <div className="flex flex-wrap gap-4 items-end">
        <label className="text-xs text-slate-400">{tr("Observation window")}<select aria-label={tr("Observation window")} className="field block mt-1" value={hours} onChange={event => changeFilter('hours', event.target.value)}>{WINDOWS.map(value => <option key={value} value={value}>{tr('Last {hours} hours', { hours: formatNumber(value) })}</option>)}</select></label>
        <label className="text-xs text-slate-400">{tr("Protocol")}<select aria-label={tr("Protocol")} className="field block mt-1" value={protocol || ''} onChange={event => changeFilter('protocol', event.target.value)}><option value="">{tr("All protocols")}</option>{NETWORK_PROTOCOLS.map(value => <option key={value} value={value}>{value}</option>)}</select></label>
        <Link to="/sources" className="text-xs text-accent py-2">{tr("Sources & coverage")}</Link>
      </div>

      <section aria-label={tr("Network overview")} className="space-y-4">
        <p className="text-xs text-slate-500">{tr('Overview across all protocols · last {hours} hours', { hours: formatNumber(hours) })}</p>
        {overview.isError ? <ErrorAlert message={tr("Network overview is unavailable. No observation totals can be confirmed.")} onRetry={() => void overview.refetch()} /> : overview.isPending ? <><p role="status" className="sr-only">{tr("Loading network overview…")}</p><CardsSkeleton count={4} /></> : counts && <>
          {overview.isFetching && <p role="status" className="text-xs text-slate-400">{tr("Updating network overview…")}</p>}
          <dl className="grid grid-cols-2 xl:grid-cols-4 gap-4">{[
            [tr("Imported observations"), counts.total_observations], [tr("Hostname observed"), counts.named_observations],
            [tr("Catalog matches"), counts.matched_observations], [tr("Unmatched observations"), counts.unmatched_observations],
          ].map(([label, value]) => <div className="stat-card" key={label}><dt className="text-xs text-slate-400">{String(label)}</dt><dd className="mt-3 text-2xl font-medium tabular-nums">{formatNumber(Number(value))}</dd></div>)}</dl>
          <dl className="flex flex-wrap gap-3" aria-label={tr("Protocol observations")}>{NETWORK_PROTOCOLS.map(name => <div key={name} className="flex gap-3 rounded-lg border border-surface-600/30 px-4 py-2 text-xs"><dt className="text-slate-400">{textLabel(name)}</dt><dd className="tabular-nums">{formatNumber((counts.protocols[name] || 0))}</dd></div>)}</dl>
          <section className="stat-card"><h2 className="text-sm font-medium flex items-center gap-2"><Activity size={16} className="text-accent" />{tr("Sensor observations")}</h2><p className="text-xs text-slate-500 mt-2">{tr("Last received metadata is not a heartbeat. Operational status and unobserved coverage are unknown.")}</p>{!counts.sensors.length ? <p className="mt-4 text-sm text-slate-400">{tr("No sensor observations in this window.")}</p> : <ul className="mt-4 grid md:grid-cols-2 gap-3">{counts.sensors.map(sensor => <li key={sensor.collector_id} className="rounded-lg border border-surface-600/30 p-3 text-xs"><div className="flex flex-wrap justify-between gap-2"><span className="font-mono break-all">{sensor.collector_id}</span><span className="text-slate-500">{tr("Status unknown")}</span></div><p className="text-slate-400 mt-2">{tr("Last observed:")} {timeLabel(sensor.last_seen)}</p><p className="text-slate-500 mt-1">{tr('{count} imported observations', { count: formatNumber(sensor.observations) })}</p></li>)}</ul>}</section>
          {!!counts.limitations.length && <details className="text-xs text-slate-400"><summary className="cursor-pointer">{tr("Collection limitations")}</summary><ul className="list-disc pl-5 mt-3 space-y-2">{counts.limitations.map((limitation, index) => <li key={index}>{limitation}</li>)}</ul></details>}
        </>}
      </section>

      <section aria-label={tr("Network events")} className="space-y-3">
        <div><h2 className="text-sm font-medium">{tr("Observation evidence")}</h2><p className="text-xs text-slate-500 mt-1">{tr("DNS is a lookup signal. A missing hostname has an unknown cause and does not establish encrypted client hello.")}</p></div>
        {events.isError ? <ErrorAlert message={tr("Network observations are unavailable. No sample data has been substituted.")} onRetry={() => void events.refetch()} /> : events.isPending ? <><p role="status" className="text-xs text-slate-400">{tr("Loading network observations…")}</p><TableSkeleton rows={5} columns={6} /></> : rows && <>
          {events.isFetching && <p role="status" className="text-xs text-slate-400">{tr("Updating network observations…")}</p>}
          {catalog.isError && <p role="status" className="text-xs text-amber-200">{tr("Service labels are unavailable. Observed hostnames are still shown.")}</p>}
          {catalog.isPending && <p className="text-xs text-slate-500">{tr("Loading service labels…")}</p>}
          {!rows.items.length ? <EmptyState icon={NetworkIcon} title={page > 1 ? tr("No observations on this page") : tr("No network observations in this selection")} description={tr("An empty result does not establish the absence of network activity or AI use.")} /> : <div className="stat-card p-0! overflow-x-auto"><table className="w-full text-sm"><thead className="text-left text-[10px] uppercase tracking-wider text-slate-500"><tr>{[tr("Observed at"), tr("Protocol"), tr("Service / hostname"), tr("Source address"), tr("Destination"), tr("Trace")].map(label => <th key={label} className="px-4 py-3 font-medium">{textLabel(label)}</th>)}</tr></thead><tbody>{rows.items.map(event => {
            const service = event.catalog_match_id ? catalogById.get(event.catalog_match_id) : undefined
            const hostname = event.domain || event.sni || event.url_host
            return <tr key={event.event_id} className="data-row align-top"><td className="px-4 py-4 text-xs text-slate-400 whitespace-nowrap">{timeLabel(event.timestamp)}</td><td className="px-4 py-4"><span className="badge bg-surface-700 text-slate-300">{event.protocol}</span></td><td className="px-4 py-4 min-w-48"><p className="font-medium break-all">{service?.canonical_name || hostname || tr("Hostname not observed")}</p>{service && <p className="text-xs text-slate-400 mt-1">{enumLabel(service.category)}</p>}{service && hostname && <p className="text-xs font-mono text-slate-500 mt-1 break-all">{hostname}</p>}<p className="text-[10px] text-slate-500 mt-2">{event.matched ? tr("Catalog association") : tr("No catalog match")}</p></td><td className="px-4 py-4 font-mono text-xs text-slate-400 break-all min-w-36">{networkEndpoint(event.src_ip)}</td><td className="px-4 py-4 font-mono text-xs text-slate-400 break-all min-w-36">{networkEndpoint(event.dst_ip, event.dst_port)}</td><td className="px-4 py-4 text-xs min-w-44"><details><summary className="cursor-pointer text-accent">{tr("Observation details")}</summary><dl className="mt-3 space-y-2 text-slate-400 break-all">{[[tr("Sensor"), event.collector_id], [tr("Parser version"), event.parser_version || tr("Not reported")], [tr("Event ID"), event.event_id], [tr("SNI"), event.sni || tr("Not observed")], [tr("HTTP host"), event.url_host || tr("Not observed")]].map(([label, value]) => <div key={label}><dt className="text-slate-500">{textLabel(label)}</dt><dd className="font-mono mt-0.5">{value}</dd></div>)}</dl></details></td></tr>
          })}</tbody></table></div>}
          <div className="flex flex-wrap justify-between items-center gap-3 text-xs text-slate-400"><p>{tr('{count} observations · page {page} of {pages}', { count: formatNumber(rows.total), page: formatNumber(page), pages: formatNumber(pages) })}</p><div className="flex gap-2"><button className="secondary-button" disabled={page <= 1 || events.isFetching} onClick={() => changeFilter('page', String(page - 1))}>{tr("Previous")}</button><button className="secondary-button" disabled={page >= pages || events.isFetching} onClick={() => changeFilter('page', String(page + 1))}>{tr("Next")}</button></div></div>
        </>}
      </section>
    </>}
  </div>
}
