import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Key, ShieldAlert } from 'lucide-react'
import { listDetections } from '@/api/detections'
import RiskBadge from '@/components/badges/RiskBadge'
import ClassificationBadge from '@/components/badges/ClassificationBadge'
import StatusBadge from '@/components/badges/StatusBadge'
import EmptyState from '@/components/ui/EmptyState'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { TableSkeleton } from '@/components/ui/LoadingSkeleton'
import { formatDistanceToNow } from 'date-fns'

export default function OAuthApps() {
  const navigate = useNavigate()

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['detections', 'oauth'],
    queryFn: () => listDetections({ entity_type: 'oauth_app', page_size: 100, sort_by: 'risk_score', sort_order: 'desc' }),
  })

  const items = data?.items || []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Key className="w-6 h-6 text-accent" />
          <h1 className="text-2xl font-bold tracking-tight">OAuth AI Apps</h1>
        </div>
        <span className="text-sm text-slate-400">{data?.total ?? 0} app{(data?.total ?? 0) !== 1 ? 's' : ''} discovered</span>
      </div>

      <p className="text-xs text-slate-400">Showing up to 100 applications. <Link to="/discoveries?entity_type=oauth_app" className="text-accent">Open the complete paginated list</Link>. Permissions indicate a grant, not confirmed access.</p>
      {items.some(d => !d.risk_score_stale && (d.risk_level === 'critical' || d.risk_level === 'high')) && (
        <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2.5 text-sm text-red-400">
          <ShieldAlert className="w-4 h-4" />
          {items.filter(d => !d.risk_score_stale && (d.risk_level === 'critical' || d.risk_level === 'high')).length} OAuth app(s) with sensitive scopes require review
        </div>
      )}

      {isLoading && <TableSkeleton rows={8} columns={7} />}
      {isError && <ErrorAlert onRetry={refetch} />}

      {!isLoading && !isError && items.length === 0 && (
        <EmptyState
          icon={Key}
          title="No OAuth AI apps discovered"
          description="Connect Microsoft 365 or Google Workspace sources to discover OAuth-connected AI applications."
        />
      )}

      {!isLoading && items.length > 0 && (
        <div className="bg-surface-800 border border-surface-600/30 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600/30 text-left text-xs text-slate-500 uppercase tracking-wider">
                <th className="px-4 py-3 font-medium">App Name</th>
                <th className="px-4 py-3 font-medium">Scopes</th>
                <th className="px-4 py-3 font-medium">Users</th>
                <th className="px-4 py-3 font-medium">Classification</th>
                <th className="px-4 py-3 font-medium">Risk</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">First Seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((d) => {
                const scopes = ((d.evidence_bundle as any)?._oauth_scopes as string[]) || []
                const hasSensitive = scopes.some(s =>
                  ['mail.read', 'files.readwrite', 'mail.send'].some(k => s.toLowerCase().includes(k))
                )
                return (
                  <tr
                    key={d.detection_id}
                    className={`data-row cursor-pointer ${hasSensitive ? 'border-l-2 border-l-red-500/50' : ''}`}
                    onClick={() => navigate(`/discoveries/${d.detection_id}`)}
                  >
                    <td className="px-4 py-3 font-medium text-slate-200"><button className="font-medium text-left hover:text-accent">{d.entity_name}</button></td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1 max-w-[300px]">
                        {scopes.slice(0, 4).map((s, i) => (
                          <span key={i} className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                            s.toLowerCase().includes('mail') || s.toLowerCase().includes('write')
                              ? 'bg-red-500/15 text-red-400'
                              : 'bg-surface-700 text-slate-400'
                          }`}>{s.split('/').pop() || s}</span>
                        ))}
                        {scopes.length > 4 && <span className="text-[10px] text-slate-500">+{scopes.length - 4}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{d.impacted_users_count}</td>
                    <td className="px-4 py-3"><ClassificationBadge classification={d.classification} /></td>
                    <td className="px-4 py-3"><RiskBadge stale={d.risk_score_stale} level={d.risk_level} score={d.risk_score} showScore /></td>
                    <td className="px-4 py-3"><StatusBadge status={d.analyst_status} /></td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {formatDistanceToNow(new Date(d.first_seen_at), { addSuffix: true })}
                    </td>
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
