import { useI18n } from '@/i18n'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Puzzle } from 'lucide-react'
import { listDetections } from '@/api/detections'
import RiskBadge from '@/components/badges/RiskBadge'
import ClassificationBadge from '@/components/badges/ClassificationBadge'
import StatusBadge from '@/components/badges/StatusBadge'
import EmptyState from '@/components/ui/EmptyState'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { TableSkeleton } from '@/components/ui/LoadingSkeleton'

export default function Extensions() {
  const { tr, formatNumber } = useI18n()

  const navigate = useNavigate()

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['detections', 'extensions'],
    queryFn: () => listDetections({ entity_type: 'browser_extension', page_size: 100, sort_by: 'risk_score', sort_order: 'desc' }),
  })

  const items = data?.items || []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Puzzle className="w-6 h-6 text-accent" />
          <h1 className="text-2xl font-bold tracking-tight">{tr("AI Browser Extensions")}</h1>
        </div>
        <span className="text-sm text-slate-400">{tr(data?.total === 1 ? '{count} extension' : '{count} extensions', { count: formatNumber(data?.total ?? 0) })}</span>
      </div>

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
    </div>
  )
}
