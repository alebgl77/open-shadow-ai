import { useState, useCallback, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { downloadBlob, downloadCsv } from '@/lib/export'
import { Search, Download, ChevronUp, ChevronDown, Filter, X } from 'lucide-react'
import { ANTI_HR_NOTICE, DETECTION_SORT_COLUMNS, exportDetections, listDetections, updateDetection, type DetectionFilter, type DetectionSortColumn } from '@/api/detections'
import RiskBadge from '@/components/badges/RiskBadge'
import ApprovalBadge from '@/components/badges/ApprovalBadge'
import ConfidenceBadge from '@/components/badges/ConfidenceBadge'
import ClassificationBadge from '@/components/badges/ClassificationBadge'
import EntityTypeBadge from '@/components/badges/EntityTypeBadge'
import StatusBadge from '@/components/badges/StatusBadge'
import SourceIcons from '@/components/ui/SourceIcons'
import EmptyState from '@/components/ui/EmptyState'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { TableSkeleton } from '@/components/ui/LoadingSkeleton'
import clsx from 'clsx'
import { formatDistanceToNow } from 'date-fns'

const PAGE_SIZES = [25, 50, 100]

export default function DiscoveryList() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  const filters: DetectionFilter = {
    search: searchParams.get('search') || undefined,
    classification: searchParams.get('classification') || undefined,
    risk_level: searchParams.get('risk_level') || undefined,
    entity_type: searchParams.get('entity_type') || undefined,
    analyst_status: searchParams.get('analyst_status') || undefined,
    page: Math.max(1, Math.floor(Number(searchParams.get('page')) || 1)),
    page_size: PAGE_SIZES.includes(Number(searchParams.get('page_size'))) ? Number(searchParams.get('page_size')) : 25,
    sort_by: (DETECTION_SORT_COLUMNS as readonly string[]).includes(searchParams.get('sort_by') || '') ? searchParams.get('sort_by') as DetectionSortColumn : 'last_seen_at',
    sort_order: searchParams.get('sort_order') || 'desc',
  }

  const [searchInput, setSearchInput] = useState(filters.search || '')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [showFilters, setShowFilters] = useState(false)
  const [confirmExport, setConfirmExport] = useState(false)
  const canEdit = useAuthStore(s => s.user?.role !== 'viewer')
  const exportAll = useMutation({
    mutationFn: () => exportDetections(filters),
    onSuccess: ({ blob, filename }) => { downloadBlob(blob, filename); setConfirmExport(false) },
  })
  useEffect(() => { setSelectedIds(new Set()); setSearchInput(searchParams.get('search') || '') }, [searchParams])

  const setFilter = useCallback((key: string, value: string | undefined) => {
    const next = new URLSearchParams(searchParams)
    if (value) next.set(key, value); else next.delete(key)
    if (key !== 'page') next.set('page', '1')
    setSearchParams(next)
  }, [searchParams, setSearchParams])

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['detections', Object.fromEntries(searchParams)],
    queryFn: () => listDetections(filters),
    placeholderData: (prev: any) => prev,
  })

  const bulkMutation = useMutation({
    mutationFn: async ({ ids, classification }: { ids: string[]; classification: string }) => {
      const results = await Promise.allSettled(ids.map(id => updateDetection(id, { classification })))
      const failures = results.filter(result => result.status === 'rejected').length
      if (failures) throw new Error(`${failures} of ${ids.length} updates failed. Refresh the list before retrying.`)
    },
    onSuccess: () => { setSelectedIds(new Set()) },
    onSettled: () => { queryClient.invalidateQueries() },
  })

  const handleSearch = () => setFilter('search', searchInput || undefined)
  const toggleSort = (col: string) => {
    if (filters.sort_by === col) {
      setFilter('sort_order', filters.sort_order === 'desc' ? 'asc' : 'desc')
    } else {
      const next = new URLSearchParams(searchParams)
      next.set('sort_by', col); next.set('sort_order', 'desc')
      setSearchParams(next)
    }
  }
  const toggleSelect = (id: string) => { const n = new Set(selectedIds); n.has(id) ? n.delete(id) : n.add(id); setSelectedIds(n) }
  const toggleSelectAll = () => {
    if (!data) return
    setSelectedIds(selectedIds.size === data.items.length ? new Set() : new Set(data.items.map(d => d.detection_id)))
  }

  const activeFilterCount = ['classification', 'risk_level', 'entity_type', 'analyst_status'].filter(k => searchParams.has(k)).length

  function SortHeader({ col, label }: { col: string; label: string }) {
    const active = filters.sort_by === col
    return (
      <th className="px-4 py-3 font-medium cursor-pointer hover:text-slate-300 transition-colors select-none">
        <button onClick={() => toggleSort(col)} className="flex items-center gap-1">
          {label}
          {active && (filters.sort_order === 'desc' ? <ChevronDown className="w-3 h-3 text-accent" /> : <ChevronUp className="w-3 h-3 text-accent" />)}
        </button>
      </th>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Discoveries</h1>
        <span className="text-sm text-slate-400">{data ? `${data.total} results` : 'Loading results…'}</span>
      </div>

      {/* Search + filter toggle */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input aria-label="Search discoveries" type="text" value={searchInput} onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()} placeholder="Search AI tools..."
            className="w-full bg-surface-800 border border-surface-600/40 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-accent/50 placeholder-slate-600" />
        </div>
        <button onClick={() => setShowFilters(!showFilters)}
          className={clsx('flex items-center gap-2 px-3 py-2 text-sm rounded-lg border transition-colors',
            showFilters || activeFilterCount > 0 ? 'bg-accent/10 text-accent border-accent/30' : 'bg-surface-800 text-slate-400 border-surface-600/40 hover:text-slate-200')}>
          <Filter className="w-4 h-4" /> Filters
          {activeFilterCount > 0 && <span className="w-5 h-5 rounded-full bg-accent text-surface-950 text-[10px] font-bold flex items-center justify-center">{activeFilterCount}</span>}
        </button>
        <button disabled={!data?.items.length} onClick={() => downloadCsv([['Tool','Type','Classification','Risk','Events','Last seen'], ...(data?.items.map(d=>[d.entity_name,d.entity_type,d.classification,d.risk_score_stale ? 'Needs recalculation' : d.risk_score,d.total_events_count,d.last_seen_at]) || [])], 'open-shadow-ai-visible-discoveries.csv')} className="flex items-center gap-2 px-3 py-2 text-sm bg-surface-800 text-slate-400 border border-surface-600/40 rounded-lg hover:text-slate-200 transition-colors">
          <Download className="w-4 h-4" /> Export page
        </button>
        {canEdit && (
          <button disabled={!data?.total} onClick={() => { exportAll.reset(); setConfirmExport(true) }} aria-expanded={confirmExport} aria-controls="export-all"
            className="flex items-center gap-2 px-3 py-2 text-sm bg-surface-800 text-slate-400 border border-surface-600/40 rounded-lg hover:text-slate-200 transition-colors">
            <Download className="w-4 h-4" /> Export all
          </button>
        )}
      </div>

      {confirmExport && (
        <section id="export-all" aria-labelledby="export-all-title" className="stat-card space-y-3">
          <h2 id="export-all-title" className="text-sm font-medium">Export all {data?.total ?? 0} matching discoveries</h2>
          <p className="text-xs text-slate-400 leading-relaxed">{ANTI_HR_NOTICE} The server records this export, with its filters, in the audit log.</p>
          <div className="flex gap-2">
            <button onClick={() => exportAll.mutate()} disabled={exportAll.isPending} className="primary-button">{exportAll.isPending ? 'Exporting…' : 'Confirm export'}</button>
            <button onClick={() => setConfirmExport(false)} className="secondary-button">Cancel</button>
          </div>
          {exportAll.isError && <p role="alert" className="text-xs text-red-400">The export could not be completed. Check your role and try again.</p>}
        </section>
      )}

      {/* Expandable filters */}
      {showFilters && (
        <div className="flex flex-wrap gap-3 bg-surface-800/50 border border-surface-600/20 rounded-lg p-4">
          {[
            { key: 'classification', label: 'Classification', options: ['unsanctioned', 'unknown', 'tolerated', 'sanctioned'] },
            { key: 'risk_level', label: 'Risk', options: ['critical', 'high', 'medium', 'low', 'info'] },
            { key: 'entity_type', label: 'Type', options: ['saas_app', 'api_service', 'browser_extension', 'oauth_app', 'local_runtime', 'local_container', 'desktop_app'] },
            { key: 'analyst_status', label: 'Status', options: ['new', 'investigating', 'classified', 'false_positive', 'escalated'] },
          ].map(f => (
            <select aria-label={f.label} key={f.key} value={(filters as any)[f.key] ?? ''} onChange={(e) => setFilter(f.key, e.target.value || undefined)}
              className="bg-surface-900 border border-surface-600/40 rounded-lg px-3 py-1.5 text-sm text-slate-300">
              <option value="">All {f.label.toLowerCase()}s</option>
              {f.options.map(o => <option key={o} value={o}>{o.replace('_', ' ')}</option>)}
            </select>
          ))}
          {activeFilterCount > 0 && (
            <button onClick={() => setSearchParams(new URLSearchParams())}
              className="flex items-center gap-1 px-3 py-1.5 text-sm text-red-400 hover:text-red-300">
              <X className="w-3 h-3" /> Clear
            </button>
          )}
        </div>
      )}

      {/* Bulk actions */}
      {canEdit && selectedIds.size > 0 && (
        <div className="flex items-center gap-4 bg-accent/5 border border-accent/20 rounded-lg px-4 py-2.5">
          <span className="text-sm text-accent font-medium">{selectedIds.size} selected</span>
          <div className="flex gap-2">
            {(['sanctioned', 'tolerated', 'unsanctioned'] as const).map(cls => (
              <button disabled={bulkMutation.isPending} key={cls} onClick={() => bulkMutation.mutate({ ids: Array.from(selectedIds), classification: cls })}
                className="px-3 py-1 text-xs bg-surface-700 text-slate-300 rounded hover:bg-surface-600 transition-colors capitalize">{cls}</button>
            ))}
          </div>
          <button onClick={() => setSelectedIds(new Set())} className="ml-auto text-xs text-slate-500 hover:text-slate-300">Deselect</button>
        </div>
      )}

      {/* Table */}
      {bulkMutation.isError && <p role="alert" className="text-sm text-red-300">{bulkMutation.error.message}</p>}
      {isLoading && <TableSkeleton rows={10} columns={9} />}
      {isError && <ErrorAlert message="Failed to load detections" onRetry={refetch} />}

      {!isLoading && !isError && (
        <div className="bg-surface-800 border border-surface-600/30 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-600/30 text-left text-xs text-slate-500 uppercase tracking-wider">
                  <th className="px-4 py-3 w-10">
                    <input aria-label="Select visible discoveries" disabled={!canEdit || bulkMutation.isPending} type="checkbox" checked={data ? selectedIds.size === data.items.length && data.items.length > 0 : false}
                      onChange={toggleSelectAll} className="rounded bg-surface-900 border-surface-600" />
                  </th>
                  <SortHeader col="entity_name" label="AI Tool" />
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Classification</th>
                  <SortHeader col="confidence_score" label="Confidence" />
                  <SortHeader col="risk_score" label="Risk" />
                  <SortHeader col="impacted_users_count" label="Users" />
                  <SortHeader col="last_seen_at" label="Last Seen" />
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Sources</th>
                </tr>
              </thead>
              <tbody>
                {data && data.items.length === 0 && (
                  <tr><td colSpan={10}>
                    <EmptyState icon={Search}
                      title={activeFilterCount > 0 ? "No results match your filters" : "No AI tools discovered yet"}
                      description={activeFilterCount > 0 ? "Try adjusting your filter criteria." : "Review source coverage and ingestion to start collecting evidence."} />
                  </td></tr>
                )}
                {data?.items.map((d) => (
                  <tr key={d.detection_id} className="data-row cursor-pointer group">
                    <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                      <input aria-label={`Select ${d.entity_name}`} disabled={!canEdit || bulkMutation.isPending} type="checkbox" checked={selectedIds.has(d.detection_id)} onChange={() => toggleSelect(d.detection_id)}
                        className="rounded bg-surface-900 border-surface-600" />
                    </td>
                    <td className="px-4 py-3" onClick={() => navigate(`/discoveries/${d.detection_id}`)}>
                      <Link to={`/discoveries/${d.detection_id}`} className="font-medium text-slate-100 group-hover:text-accent transition-colors">{d.entity_name}</Link>
                    </td>
                    <td className="px-4 py-3" onClick={() => navigate(`/discoveries/${d.detection_id}`)}><EntityTypeBadge entityType={d.entity_type} showLabel={false} /></td>
                    <td className="px-4 py-3" onClick={() => navigate(`/discoveries/${d.detection_id}`)}><div className="flex flex-wrap gap-1"><ClassificationBadge classification={d.classification} /><ApprovalBadge status={d.governance_status} /></div></td>
                    <td className="px-4 py-3" onClick={() => navigate(`/discoveries/${d.detection_id}`)}><ConfidenceBadge level={d.confidence_level} score={d.confidence_score} showScore /></td>
                    <td className="px-4 py-3" onClick={() => navigate(`/discoveries/${d.detection_id}`)}><RiskBadge stale={d.risk_score_stale} level={d.risk_level} score={d.risk_score} showScore /></td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400" onClick={() => navigate(`/discoveries/${d.detection_id}`)}>{d.impacted_users_count}</td>
                    <td className="px-4 py-3 text-xs text-slate-400" onClick={() => navigate(`/discoveries/${d.detection_id}`)}>
                      {formatDistanceToNow(new Date(d.last_seen_at), { addSuffix: true })}
                    </td>
                    <td className="px-4 py-3" onClick={() => navigate(`/discoveries/${d.detection_id}`)}><StatusBadge status={d.analyst_status} /></td>
                    <td className="px-4 py-3" onClick={() => navigate(`/discoveries/${d.detection_id}`)}><SourceIcons sources={d.source_types} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {data && data.total > 0 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-surface-600/30">
              <div className="flex items-center gap-3">
                <span className="text-xs text-slate-500">
                  {((filters.page! - 1) * filters.page_size! + 1)}–{Math.min(filters.page! * filters.page_size!, data.total)} of {data.total}
                </span>
                <select aria-label="Results per page" value={filters.page_size} onChange={(e) => setFilter('page_size', e.target.value)}
                  className="bg-surface-900 border border-surface-600/40 rounded px-2 py-1 text-xs text-slate-400">
                  {PAGE_SIZES.map(s => <option key={s} value={s}>{s}/page</option>)}
                </select>
              </div>
              <div className="flex gap-2">
                <button disabled={filters.page! <= 1} onClick={() => setFilter('page', String(filters.page! - 1))}
                  className="px-3 py-1 text-xs bg-surface-700 rounded hover:bg-surface-600 disabled:opacity-30 transition-colors">Previous</button>
                <button disabled={filters.page! * filters.page_size! >= data.total} onClick={() => setFilter('page', String(filters.page! + 1))}
                  className="px-3 py-1 text-xs bg-surface-700 rounded hover:bg-surface-600 disabled:opacity-30 transition-colors">Next</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
