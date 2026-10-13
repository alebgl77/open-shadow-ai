import { useI18n } from '@/i18n'
import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { ChevronDown, ChevronUp, Download, Info, Puzzle, Shield } from 'lucide-react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { ANTI_HR_NOTICE, listDetections, type DetectionListResponse } from '@/api/detections'
import {
  CATALOG_MATCHES, ENABLED_STATES, INSTALL_SOURCES, INVENTORY_NOTICE, INVENTORY_SORT_COLUMNS, INVENTORY_WINDOWS, SORT_ORDERS,
  enabledState, exportExtensionInventory, getExtensionInventory, getExtensionVersions, getInventorySummary, getVersionChanges,
  type ExtensionInventoryItem, type IdentityMode, type IdentityWindow, type InventoryFilters, type InventorySortColumn, type VersionChangeFilters,
} from '@/api/inventory'
import RiskBadge from '@/components/badges/RiskBadge'
import ClassificationBadge from '@/components/badges/ClassificationBadge'
import StatusBadge from '@/components/badges/StatusBadge'
import EnabledBadge from '@/components/badges/EnabledBadge'
import InstallSourceBadge from '@/components/badges/InstallSourceBadge'
import EmptyState from '@/components/ui/EmptyState'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { CardsSkeleton, TableSkeleton } from '@/components/ui/LoadingSkeleton'
import { downloadBlob, downloadCsv } from '@/lib/export'
import { useAuthStore } from '@/stores/auth'
import type { MessageKey } from '@/i18n/messages'

const VIEWS = ['matches', 'inventory', 'changes'] as const
type View = typeof VIEWS[number]
const PAGE_SIZE = 25
const INSTALL_SOURCE_LABELS: Record<string, MessageKey> = {
  store: 'Store', user: 'User-installed', unpacked: 'Unpacked', external: 'External installer', policy: 'Policy',
  component: 'Browser component', orphan: 'Orphan', unknown: 'Unknown source',
}
const forbidden = (error: unknown) => isAxiosError(error) && error.response?.status === 403
const oneOf = <T extends string>(values: readonly T[], value: string | null): T | undefined => (values as readonly string[]).includes(value ?? '') ? value as T : undefined
const positivePage = (value: string | null) => { const page = Number(value); return Number.isSafeInteger(page) && page > 0 ? page : 1 }
const text = (value: string | null) => value?.trim() || undefined

function useInventoryAccess() {
  const mode = useAuthStore(state => state.mode)
  const session = useAuthStore(state => state.session)
  const role = useAuthStore(state => state.user?.role)
  return { mode, session, canRead: role === 'admin' || role === 'analyst' }
}

function useFilterParams() {
  const [params, setParams] = useSearchParams()
  const changeFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    if (key !== 'page') next.set('page', '1')
    setParams(next)
  }
  return { params, setParams, changeFilter }
}

export default function Extensions() {
  const { tr, formatNumber } = useI18n()

  const [params, setParams] = useSearchParams()
  const view = oneOf(VIEWS, params.get('view')) || 'matches'
  const matches = useQuery({
    queryKey: ['detections', 'extensions'],
    queryFn: () => listDetections({ entity_type: 'browser_extension', page_size: 100, sort_by: 'risk_score', sort_order: 'desc' }),
    enabled: view === 'matches',
  })
  const labels: Record<View, string> = { matches: tr("Catalog matches"), inventory: tr("Inventory"), changes: tr("Version changes") }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Puzzle className="w-6 h-6 text-accent" />
          <h1 className="text-2xl font-bold tracking-tight">{tr("AI Browser Extensions")}</h1>
        </div>
        {view === 'matches' && <span className="text-sm text-slate-400">{tr(matches.data?.total === 1 ? '{count} extension' : '{count} extensions', { count: formatNumber(matches.data?.total ?? 0) })}</span>}
      </div>
      <div className="flex flex-wrap gap-2" role="tablist" aria-label={tr("Extension views")}>
        {VIEWS.map(name => <button role="tab" aria-selected={view === name} className={view === name ? 'primary-button' : 'secondary-button'} key={name} onClick={() => setParams(new URLSearchParams({ view: name }))}>{labels[name]}</button>)}
      </div>
      {view === 'matches' ? <MatchesView data={matches.data} isLoading={matches.isLoading} isError={matches.isError} refetch={() => void matches.refetch()} /> : view === 'inventory' ? <InventoryView /> : <ChangesView />}
    </div>
  )
}

function MatchesView({ data, isLoading, isError, refetch }: { data?: DetectionListResponse; isLoading: boolean; isError: boolean; refetch: () => void }) {
  const { tr, formatNumber } = useI18n()

  const navigate = useNavigate()
  const items = data?.items || []
  return <>
    <p className="text-xs text-slate-400">{tr("Showing up to 100 extensions.")} <Link to="/discoveries?entity_type=browser_extension" className="text-accent">{tr("Open the complete paginated list")}</Link>{tr(". Installation does not establish active use.")}</p>{isLoading && <TableSkeleton rows={8} columns={6} />}
    {isError && <ErrorAlert onRetry={refetch} />}

    {!isLoading && !isError && items.length === 0 && (
      <EmptyState
        icon={Puzzle}
        title={tr("No AI browser extensions detected")}
        description={tr("Deploy the endpoint agent on managed devices to discover installed AI browser extensions.")}
      />
    )}

    {!isLoading && items.length > 0 && (
      <div className="bg-surface-800 border border-surface-600/30 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-surface-600/30 text-left text-xs text-slate-500 uppercase tracking-wider">
              <th className="px-4 py-3 font-medium">{tr("Extension")}</th>
              <th className="px-4 py-3 font-medium">{tr("Extension ID")}</th>
              <th className="px-4 py-3 font-medium">{tr("Devices")}</th>
              <th className="px-4 py-3 font-medium">{tr("Classification")}</th>
              <th className="px-4 py-3 font-medium">{tr("Risk")}</th>
              <th className="px-4 py-3 font-medium">{tr("Status")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((d) => {
              const browserEvidence = (d.evidence_bundle as Record<string, any>)?.browser
              return (
                <tr
                  key={d.detection_id}
                  className="data-row cursor-pointer"
                  onClick={() => navigate(`/discoveries/${d.detection_id}`)}
                >
                  <td className="px-4 py-3 font-medium text-slate-200"><button className="font-medium text-left hover:text-accent">{d.entity_name}</button></td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500 max-w-[200px] truncate">
                    {browserEvidence?.sample_values?.[0] || d.catalog_item_id || '—'}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">{formatNumber(d.impacted_devices_count)}</td>
                  <td className="px-4 py-3"><ClassificationBadge classification={d.classification} /></td>
                  <td className="px-4 py-3"><RiskBadge stale={d.risk_score_stale} level={d.risk_level} /></td>
                  <td className="px-4 py-3"><StatusBadge status={d.analyst_status} /></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    )}
  </>
}

function AccessAlert() {
  const { tr } = useI18n()
  return <section role="alert" className="stat-card flex gap-3 items-start"><Shield size={20} className="text-amber-300 shrink-0" /><div><h2 className="text-sm font-medium">{tr("Extension inventory access requires an analyst or administrator role.")}</h2><p className="text-xs text-slate-400 mt-2">{tr("Your current permissions do not allow access to per-host and per-user installation records.")}</p></div></section>
}

function InventoryNotice({ window, identityMode }: { window?: IdentityWindow; identityMode?: IdentityMode }) {
  const { tr, textLabel, formatDate, formatNumber } = useI18n()
  const mode = useAuthStore(state => state.mode)
  return <>
    {mode === 'demo' && <p role="status" className="text-xs text-amber-200">{tr("Synthetic extension inventory · fictional hosts, pseudonymous users and illustrative versions.")}</p>}
    <div className="flex gap-3 rounded-xl border border-accent/20 bg-accent/5 p-4 text-xs text-slate-300 leading-relaxed"><Info size={16} className="text-accent shrink-0" /><p>{textLabel(INVENTORY_NOTICE)}{' '}{identityMode === 'pseudonymized' ? tr("The current privacy setting pseudonymises identities in newly processed events.") : identityMode === 'raw' ? tr("The current privacy setting keeps identities as reported in newly processed events.") : null}{' '}{identityMode && tr("Existing labels may retain their previous form until the next snapshot after a privacy setting change.")}{' '}{window && tr('Installations reported within the last {days} days are shown, as of {time}.', { days: formatNumber(window.days), time: formatDate(window.as_of) })}</p></div>
    <p className="text-xs text-slate-400 leading-relaxed">{tr("Not observed is inferred from the device's most recent received extension events. Partial collection, failures, truncation or partial ingestion can hide an installation; this does not prove removal.")}</p>
  </>
}

function BrowserFilter({ value, options, onChange }: { value?: string; options: string[]; onChange: (value: string) => void }) {
  const { tr } = useI18n()
  const browsers = [...new Set([...options, ...(value ? [value] : [])])].sort()
  return <label className="text-xs text-slate-400">{tr("Browser")}<select aria-label={tr("Browser")} className="field block mt-1" value={value || ''} onChange={event => onChange(event.target.value)}><option value="">{tr("All browsers")}</option>{browsers.map(name => <option key={name} value={name}>{name}</option>)}</select></label>
}

function TextFilter({ label, value, onApply }: { label: string; value: string; onApply: (value: string) => void }) {
  const [input, setInput] = useState(value)
  useEffect(() => { setInput(value) }, [value])
  return <label className="text-xs text-slate-400">{label}<input aria-label={label} type="text" className="field block mt-1" value={input} onChange={event => setInput(event.target.value)} onBlur={() => onApply(input.trim())} onKeyDown={event => { if (event.key === 'Enter') onApply(input.trim()) }} /></label>
}

function Pager({ page, pages, busy, onPage }: { page: number; pages: number; busy: boolean; onPage: (page: number) => void }) {
  const { tr } = useI18n()
  return <div className="flex gap-2"><button className="secondary-button" disabled={page <= 1 || busy} onClick={() => onPage(page - 1)}>{tr("Previous")}</button><button className="secondary-button" disabled={page >= pages || busy} onClick={() => onPage(page + 1)}>{tr("Next")}</button></div>
}

function UserProfile({ userLabel, profile }: { userLabel: string | null; profile: string }) {
  const { tr } = useI18n()
  if (userLabel == null && !profile) return <span className="text-slate-500">{tr("Host-level record")}</span>
  return <span className="font-mono text-xs break-all">{userLabel ?? tr("Not reported")} · {profile || tr("Not reported")}</span>
}

function VersionHistory({ item }: { item: ExtensionInventoryItem }) {
  const { tr, formatDate } = useI18n()
  const { mode, session } = useInventoryAccess()
  const [open, setOpen] = useState(false)
  const history = useQuery({
    queryKey: ['extension-versions', mode, session, item.inventory_key],
    queryFn: ({ signal }) => getExtensionVersions(item.inventory_key, signal), enabled: open, retry: false,
  })
  return <details onToggle={event => setOpen(event.currentTarget.open)}>
    <summary className="cursor-pointer text-accent">{tr("Version history")}</summary>
    {open && <div className="mt-3 text-slate-400 min-w-44">
      {history.isError ? <p role="alert">{tr("Version history is unavailable.")} <button className="text-accent underline" onClick={() => void history.refetch()}>{tr("Retry")}</button></p>
        : history.isPending ? <p role="status">{tr("Loading version history…")}</p>
        : !history.data.changes.length ? <p>{tr("No version change observed within the identity window.")}</p>
        : <ol className="space-y-2">{history.data.changes.map(change => <li key={change.change_id}><span className="font-mono text-slate-200">{change.from_version ?? tr("First reported version")} → {change.to_version ?? tr("Not reported")}</span><span className="block text-[10px] text-slate-500 mt-0.5">{formatDate(change.observed_at)}</span></li>)}</ol>}
    </div>}
  </details>
}

function InventoryView() {
  const { tr, textLabel, formatDate, formatNumber } = useI18n()
  const installSourceLabel = (source: string) => Object.hasOwn(INSTALL_SOURCE_LABELS, source) ? tr(INSTALL_SOURCE_LABELS[source]) : source

  const { params, setParams, changeFilter } = useFilterParams()
  const { mode, session, canRead } = useInventoryAccess()
  const filters: InventoryFilters = {
    host: text(params.get('host')), browser: text(params.get('browser')), enabled: oneOf(ENABLED_STATES, params.get('enabled')),
    install_source: (params.get('install_source') || '').split(',').filter(value => (INSTALL_SOURCES as readonly string[]).includes(value)).join(',') || undefined,
    catalog_match: oneOf(CATALOG_MATCHES, params.get('catalog_match')), extension_id: text(params.get('extension_id')), search: text(params.get('search')),
    page: positivePage(params.get('page')), page_size: PAGE_SIZE,
    sort_by: oneOf(INVENTORY_SORT_COLUMNS, params.get('sort_by')) || 'last_seen_at', sort_order: oneOf(SORT_ORDERS, params.get('sort_order')) || 'desc',
  }
  const summary = useQuery({
    queryKey: ['extension-inventory-summary', mode, session],
    queryFn: ({ signal }) => getInventorySummary(signal), enabled: canRead, retry: false,
  })
  const inventory = useQuery({
    queryKey: ['extension-inventory', mode, session, filters],
    queryFn: ({ signal }) => getExtensionInventory(filters, signal), enabled: canRead, retry: false,
  })
  const [confirmExport, setConfirmExport] = useState(false)
  useEffect(() => { setConfirmExport(false) }, [params])
  const exportAll = useMutation({
    mutationFn: () => exportExtensionInventory(filters),
    onSuccess: ({ blob, filename }) => { downloadBlob(blob, filename); setConfirmExport(false) },
  })
  const toggleSort = (column: InventorySortColumn) => {
    if (filters.sort_by === column) { changeFilter('sort_order', filters.sort_order === 'desc' ? 'asc' : 'desc'); return }
    const next = new URLSearchParams(params)
    next.set('sort_by', column); next.set('sort_order', 'desc'); next.set('page', '1')
    setParams(next)
  }
  const permissionDenied = !canRead || forbidden(inventory.error) || forbidden(summary.error)
  const counts = summary.isError ? undefined : summary.data
  const rows = inventory.isError ? undefined : inventory.data
  const page = filters.page
  const pages = Math.max(1, Math.ceil((rows?.total || 0) / PAGE_SIZE))
  const actionsDisabled = inventory.isPending || inventory.isError || inventory.isFetching
  const sortHeader = (label: string, column?: InventorySortColumn) => <th key={label} className="px-4 py-3 font-medium whitespace-nowrap">{column ? <button onClick={() => toggleSort(column)} className="flex items-center gap-1 uppercase">{label}{filters.sort_by === column && (filters.sort_order === 'desc' ? <ChevronDown className="w-3 h-3 text-accent" /> : <ChevronUp className="w-3 h-3 text-accent" />)}</button> : label}</th>
  const exportPage = () => downloadCsv([
    ['Host', 'User', 'Browser', 'Profile', 'Extension', 'Extension ID', 'Version', 'Enabled', 'Install source', 'Installed at', 'First seen', 'Last seen', 'Present in latest snapshot', 'Catalog item'],
    ...(rows?.items.map(item => [item.host_label, item.user_label ?? '', item.browser, item.profile, item.extension_name, item.extension_id, item.version ?? '', enabledState(item.enabled), item.install_source, item.installed_at ?? '', item.first_seen_at, item.last_seen_at, item.present_in_latest_snapshot, item.catalog_item_id ?? '']) || []),
  ], 'open-shadow-ai-visible-extension-inventory.csv')

  if (permissionDenied) return <AccessAlert />
  return <>
    <InventoryNotice window={rows?.identity_window ?? counts?.identity_window} identityMode={rows?.identity_mode ?? counts?.identity_mode} />

    <section aria-label={tr("Inventory overview")} className="space-y-4">
      {summary.isError ? <ErrorAlert message={tr("The inventory summary is unavailable. No installation totals can be confirmed.")} onRetry={() => void summary.refetch()} /> : summary.isPending ? <><p role="status" className="sr-only">{tr("Loading inventory summary…")}</p><CardsSkeleton count={5} /></> : counts && <>
        <dl className="grid grid-cols-2 xl:grid-cols-5 gap-4">{[
          [tr("Installations"), counts.installations], [tr("Hosts"), counts.hosts], [tr("Distinct extensions"), counts.extensions],
          [tr("Catalog matches"), counts.catalog_matched], [tr("Version changes (7 days)"), counts.version_changes_7d],
        ].map(([label, value]) => <div className="stat-card" key={label}><dt className="text-xs text-slate-400">{String(label)}</dt><dd className="mt-3 text-2xl font-medium tabular-nums">{formatNumber(Number(value))}</dd></div>)}</dl>
        <dl className="flex flex-wrap gap-3" aria-label={tr("Installations by state")}>{[
          ...ENABLED_STATES.map(state => [<EnabledBadge key={state} enabled={state} />, counts.by_enabled[state] || 0] as const),
          ...Object.entries(counts.by_install_source).map(([source, count]) => [<InstallSourceBadge key={source || 'not-reported'} source={source} />, count] as const),
        ].map(([badge, count], index) => <div key={index} className="flex items-center gap-3 rounded-lg border border-surface-600/30 px-3 py-2 text-xs"><dt>{badge}</dt><dd className="tabular-nums">{formatNumber(count)}</dd></div>)}</dl>
        {!!counts.limitations.length && <details className="text-xs text-slate-400"><summary className="cursor-pointer">{tr("Collection limitations")}</summary><ul className="list-disc pl-5 mt-3 space-y-2">{counts.limitations.map((limitation, index) => <li key={index}>{textLabel(limitation)}</li>)}</ul></details>}
      </>}
    </section>

    <div className="flex flex-wrap gap-4 items-end">
      <TextFilter label={tr("Search extensions")} value={filters.search || ''} onApply={value => { if (value !== (filters.search || '')) changeFilter('search', value) }} />
      <TextFilter label={tr("Host")} value={filters.host || ''} onApply={value => { if (value !== (filters.host || '')) changeFilter('host', value) }} />
      <BrowserFilter value={filters.browser} options={Object.keys(counts?.by_browser || {})} onChange={value => changeFilter('browser', value)} />
      <label className="text-xs text-slate-400">{tr("Enabled state")}<select aria-label={tr("Enabled state")} className="field block mt-1" value={filters.enabled || ''} onChange={event => changeFilter('enabled', event.target.value)}><option value="">{tr("Any state")}</option><option value="true">{tr("Enabled")}</option><option value="false">{tr("Disabled")}</option><option value="unknown">{tr("State not reported")}</option></select></label>
      <label className="text-xs text-slate-400">{tr("Install source")}<select aria-label={tr("Install source")} className="field block mt-1" value={filters.install_source || ''} onChange={event => changeFilter('install_source', event.target.value)}><option value="">{tr("Any source")}</option>{INSTALL_SOURCES.map(source => <option key={source} value={source}>{installSourceLabel(source)}</option>)}{filters.install_source?.includes(',') && <option value={filters.install_source}>{filters.install_source.split(',').map(installSourceLabel).join(', ')}</option>}</select></label>
      <label className="text-xs text-slate-400">{tr("Catalog match")}<select aria-label={tr("Catalog match")} className="field block mt-1" value={filters.catalog_match || ''} onChange={event => changeFilter('catalog_match', event.target.value)}><option value="">{tr("Matched and unmatched")}</option><option value="matched">{tr("Catalog association")}</option><option value="unmatched">{tr("No catalog match")}</option></select></label>
      <button disabled={actionsDisabled || !rows?.items.length} onClick={exportPage} className="secondary-button"><Download className="w-4 h-4" />{tr("Export page")}</button>
      <button disabled={actionsDisabled || !rows?.total} onClick={() => { exportAll.reset(); setConfirmExport(true) }} aria-expanded={confirmExport} aria-controls="export-inventory" className="secondary-button"><Download className="w-4 h-4" />{tr("Export all")}</button>
    </div>

    {confirmExport && (
      <section id="export-inventory" aria-labelledby="export-inventory-title" className="stat-card space-y-3">
        <h2 id="export-inventory-title" className="text-sm font-medium">{tr('Export all {count} matching installations', { count: formatNumber(rows?.total ?? 0) })}</h2>
        <p className="text-xs text-slate-400 leading-relaxed">{textLabel(ANTI_HR_NOTICE)}{' '}{tr("The server records this export, with its filters, in the audit log.")}</p>
        <div className="flex gap-2">
          <button onClick={() => exportAll.mutate()} disabled={actionsDisabled || exportAll.isPending} className="primary-button">{exportAll.isPending ? tr("Exporting…") : tr("Confirm export")}</button>
          <button onClick={() => setConfirmExport(false)} className="secondary-button">{tr("Cancel")}</button>
        </div>
        {exportAll.isError && <p role="alert" className="text-xs text-red-400">{tr("The export could not be completed. Check your role and try again.")}</p>}
      </section>
    )}

    <section aria-label={tr("Extension installations")} className="space-y-3">
      {inventory.isError ? <ErrorAlert message={tr("The extension inventory is unavailable. No sample data has been substituted.")} onRetry={() => void inventory.refetch()} /> : inventory.isPending ? <><p role="status" className="text-xs text-slate-400">{tr("Loading extension inventory…")}</p><TableSkeleton rows={5} columns={8} /></> : rows && <>
        {inventory.isFetching && <p role="status" className="text-xs text-slate-400">{tr("Updating extension inventory…")}</p>}
        {!rows.items.length ? <EmptyState icon={Puzzle} title={page > 1 ? tr("No installations on this page") : tr("No installations in this selection")} description={tr("An empty inventory does not establish the absence of extensions. Only hosts running the endpoint agent with browser collection are covered.")} /> : <div className="stat-card p-0! overflow-x-auto"><table className="w-full text-sm"><thead className="text-left text-[10px] uppercase tracking-wider text-slate-500"><tr>
          {sortHeader(tr("Extension"), 'extension_name')}{sortHeader(tr("Browser"), 'browser')}{sortHeader(tr("Host"), 'host_label')}{sortHeader(tr("User · Profile"))}{sortHeader(tr("Version"), 'version')}{sortHeader(tr("Enabled"))}{sortHeader(tr("Install source"))}{sortHeader(tr("Installed at"), 'installed_at')}{sortHeader(tr("Catalog"))}{sortHeader(tr("Last seen"), 'last_seen_at')}{sortHeader(tr("History"))}
        </tr></thead><tbody>{rows.items.map(item => <tr key={item.inventory_key} className="data-row align-top">
          <td className="px-4 py-4 min-w-48"><p className="font-medium break-all">{item.extension_name || tr("Unnamed extension")}</p><p className="text-xs font-mono text-slate-500 mt-1 break-all">{item.extension_id}</p></td>
          <td className="px-4 py-4 text-xs text-slate-300">{item.browser}</td>
          <td className="px-4 py-4 font-mono text-xs text-slate-400 break-all">{item.host_label}</td>
          <td className="px-4 py-4 text-xs text-slate-400"><UserProfile userLabel={item.user_label} profile={item.profile} /></td>
          <td className="px-4 py-4 font-mono text-xs text-slate-300 whitespace-nowrap">{item.version ?? <span className="font-sans text-slate-500">{tr("Not reported")}</span>}</td>
          <td className="px-4 py-4"><EnabledBadge enabled={item.enabled} /></td>
          <td className="px-4 py-4"><InstallSourceBadge source={item.install_source} /></td>
          <td className="px-4 py-4 text-xs text-slate-400 whitespace-nowrap">{item.installed_at ? formatDate(item.installed_at) : tr("Not reported")}</td>
          <td className="px-4 py-4 text-xs whitespace-nowrap">{item.detection_id ? <Link to={`/discoveries/${item.detection_id}`} className="text-accent">{tr("Open discovery")}</Link> : <span className="text-slate-500">{tr(item.catalog_item_id != null ? "Catalog association" : "No catalog match")}</span>}</td>
          <td className="px-4 py-4 text-xs text-slate-400 whitespace-nowrap">{formatDate(item.last_seen_at)}{!item.present_in_latest_snapshot && <p className="text-amber-300 mt-1">{tr("Not observed in the latest received extension events")}</p>}</td>
          <td className="px-4 py-4 text-xs"><VersionHistory item={item} /></td>
        </tr>)}</tbody></table></div>}
        <div className="flex flex-wrap justify-between items-center gap-3 text-xs text-slate-400"><p>{tr('{count} installations · page {page} of {pages}', { count: formatNumber(rows.total), page: formatNumber(page), pages: formatNumber(pages) })}</p><Pager page={page} pages={pages} busy={inventory.isFetching} onPage={next => changeFilter('page', String(next))} /></div>
      </>}
    </section>
  </>
}

function ChangesView() {
  const { tr, formatDate, formatNumber } = useI18n()

  const { params, changeFilter } = useFilterParams()
  const { mode, session, canRead } = useInventoryAccess()
  const hours = (INVENTORY_WINDOWS as readonly number[]).includes(Number(params.get('hours'))) ? Number(params.get('hours')) : 24
  const filters: VersionChangeFilters = { hours, host: text(params.get('host')), browser: text(params.get('browser')), extension_id: text(params.get('extension_id')), page: positivePage(params.get('page')), page_size: PAGE_SIZE }
  const summary = useQuery({
    queryKey: ['extension-inventory-summary', mode, session],
    queryFn: ({ signal }) => getInventorySummary(signal), enabled: canRead, retry: false,
  })
  const changes = useQuery({
    queryKey: ['extension-version-changes', mode, session, filters],
    queryFn: ({ signal }) => getVersionChanges(filters, signal), enabled: canRead, retry: false,
  })
  const permissionDenied = !canRead || forbidden(changes.error) || forbidden(summary.error)
  const counts = summary.isError ? undefined : summary.data
  const rows = changes.isError ? undefined : changes.data
  const page = filters.page
  const pages = Math.max(1, Math.ceil((rows?.total || 0) / PAGE_SIZE))

  if (permissionDenied) return <AccessAlert />
  return <>
    <InventoryNotice window={rows?.identity_window ?? counts?.identity_window} identityMode={rows?.identity_mode ?? counts?.identity_mode} />
    <div className="flex flex-wrap gap-4 items-end">
      <label className="text-xs text-slate-400">{tr("Change window")}<select aria-label={tr("Change window")} className="field block mt-1" value={hours} onChange={event => changeFilter('hours', event.target.value)}>{INVENTORY_WINDOWS.map(value => <option key={value} value={value}>{tr('Last {hours} hours', { hours: formatNumber(value) })}</option>)}</select></label>
      <TextFilter label={tr("Host")} value={filters.host || ''} onApply={value => { if (value !== (filters.host || '')) changeFilter('host', value) }} />
      <BrowserFilter value={filters.browser} options={Object.keys(counts?.by_browser || {})} onChange={value => changeFilter('browser', value)} />
      <TextFilter label={tr("Extension ID")} value={filters.extension_id || ''} onApply={value => { if (value !== (filters.extension_id || '')) changeFilter('extension_id', value) }} />
    </div>
    <section aria-label={tr("Version changes")} className="space-y-3">
      <div><h2 className="text-sm font-medium">{tr("Observed version changes")}</h2><p className="text-xs text-slate-500 mt-1">{tr("A change is recorded when an installation reports a different version than before. A version change is not a security event by itself.")}</p></div>
      {changes.isError ? <ErrorAlert message={tr("Version changes are unavailable. No sample data has been substituted.")} onRetry={() => void changes.refetch()} /> : changes.isPending ? <><p role="status" className="text-xs text-slate-400">{tr("Loading version changes…")}</p><TableSkeleton rows={5} columns={5} /></> : rows && <>
        {changes.isFetching && <p role="status" className="text-xs text-slate-400">{tr("Updating version changes…")}</p>}
        {!rows.items.length ? <EmptyState icon={Puzzle} title={page > 1 ? tr("No version changes on this page") : tr("No version changes in this window")} description={tr("An empty result does not establish that no extension was updated; only reported installations inside the identity window are covered.")} /> : <div className="stat-card p-0! overflow-x-auto"><table className="w-full text-sm"><thead className="text-left text-[10px] uppercase tracking-wider text-slate-500"><tr>{[tr("Observed at"), tr("Extension"), tr("Browser"), tr("Host · User · Profile"), tr("Change")].map(label => <th key={label} className="px-4 py-3 font-medium">{label}</th>)}</tr></thead><tbody>{rows.items.map(change => <tr key={change.change_id} className="data-row align-top">
          <td className="px-4 py-4 text-xs text-slate-400 whitespace-nowrap">{formatDate(change.observed_at)}</td>
          <td className="px-4 py-4 min-w-48"><p className="font-medium break-all">{change.extension_name || tr("Unnamed extension")}</p><p className="text-xs font-mono text-slate-500 mt-1 break-all">{change.extension_id}</p></td>
          <td className="px-4 py-4 text-xs text-slate-300">{change.browser}</td>
          <td className="px-4 py-4 font-mono text-xs text-slate-400 break-all">{change.host_label} · {change.user_label ?? tr("Not reported")} · {change.profile || tr("Not reported")}</td>
          <td className="px-4 py-4 font-mono text-xs text-slate-200 whitespace-nowrap">{change.from_version ?? tr("First reported version")} → {change.to_version ?? tr("Not reported")}</td>
        </tr>)}</tbody></table></div>}
        <div className="flex flex-wrap justify-between items-center gap-3 text-xs text-slate-400"><p>{tr('{count} version changes · page {page} of {pages}', { count: formatNumber(rows.total), page: formatNumber(page), pages: formatNumber(pages) })}{rows.since && rows.until && <> {tr('Changes observed between {since} and {until}; history is kept for {days} days.', { since: formatDate(rows.since), until: formatDate(rows.until), days: formatNumber(rows.identity_window.days) })}</>}</p><Pager page={page} pages={pages} busy={changes.isFetching} onPage={next => changeFilter('page', String(next))} /></div>
      </>}
    </section>
  </>
}
