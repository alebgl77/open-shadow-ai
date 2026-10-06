import { useQuery } from '@tanstack/react-query'
import { Shield } from 'lucide-react'
import { listGovernance } from '@/api/governance'
import ClassificationBadge from '@/components/badges/ClassificationBadge'
import ApprovalBadge from '@/components/badges/ApprovalBadge'
import EmptyState from '@/components/ui/EmptyState'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { TableSkeleton } from '@/components/ui/LoadingSkeleton'
import { formatDistanceToNow } from 'date-fns'

export default function Governance() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['governance'],
    queryFn: () => listGovernance(),
  })

  const items = data || []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-accent" />
          <h1 className="text-2xl font-bold tracking-tight">Governance Policies</h1>
        </div>
        <span className="text-sm text-slate-400">{items.length} polic{items.length !== 1 ? 'ies' : 'y'}</span>
      </div>

      <p className="text-sm text-slate-400">
        Governance policies define the organizational classification for AI tools.
        Review policy intent alongside the current classification on each detection. Enforcement labels record intent; this console does not block AI requests.
      </p>

      {isLoading && <TableSkeleton rows={6} columns={6} />}
      {isError && <ErrorAlert onRetry={refetch} />}

      {!isLoading && !isError && items.length === 0 && (
        <EmptyState
          icon={Shield}
          title="No governance policies defined"
          description="Administrators can create policies through the governance API. Review observed tools in Discoveries before recording a decision."
        />
      )}

      {!isLoading && items.length > 0 && (
        <div className="bg-surface-800 border border-surface-600/30 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600/30 text-left text-xs text-slate-500 uppercase tracking-wider">
                <th className="px-4 py-3 font-medium">Target</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Classification</th>
                <th className="px-4 py-3 font-medium">Owner</th>
                <th className="px-4 py-3 font-medium">Mode</th>
                <th className="px-4 py-3 font-medium">Expires</th>
                <th className="px-4 py-3 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {items.map((g) => (
                <tr key={g.governance_id} className="data-row">
                  <td className="px-4 py-3 font-medium font-mono text-slate-200">{g.target_id}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">{g.target_type}</td>
                  <td className="px-4 py-3"><div className="flex flex-wrap gap-1"><ClassificationBadge classification={g.org_classification} /><ApprovalBadge status={g.approval_status} /></div></td>
                  <td className="px-4 py-3 text-xs text-slate-400">{g.owner || '—'}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-surface-700 px-2 py-0.5 rounded-sm">{g.enforcement_mode}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {g.approved_until ? formatDistanceToNow(new Date(g.approved_until), { addSuffix: true }) : 'Never'}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {formatDistanceToNow(new Date(g.created_at), { addSuffix: true })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
