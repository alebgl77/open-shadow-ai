import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Users, Search } from 'lucide-react'
import { listDetections } from '@/api/detections'
import RiskBadge from '@/components/badges/RiskBadge'
import SourceIcons from '@/components/ui/SourceIcons'
import EmptyState from '@/components/ui/EmptyState'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { TableSkeleton } from '@/components/ui/LoadingSkeleton'
import { formatDistanceToNow } from 'date-fns'

export default function UserView() {

  const [search, setSearch] = useState('')

  // Aggregate detections by user via the detections endpoint
  // In a full implementation this would hit /api/v1/users-view
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['detections-for-users'],
    queryFn: () => listDetections({ page_size: 100, sort_by: 'impacted_users_count', sort_order: 'desc' }),
  })

  // Build user-centric view from detections
  const userMap = new Map<string, { tools: string[]; maxRisk: string; maxRiskScore: number; riskStale: boolean; lastSeen: string; sources: Set<string> }>()
  if (data?.items) {
    for (const d of data.items) {
      const evidence = d.evidence_bundle as Record<string, unknown>
      const users = (evidence?._users as string[]) || []
      for (const user of users) {
        if (search && !user.toLowerCase().includes(search.toLowerCase())) continue
        const existing = userMap.get(user) || { tools: [], maxRisk: 'info', maxRiskScore: 0, riskStale: false, lastSeen: '', sources: new Set<string>() }
        existing.tools.push(d.entity_name)
        existing.riskStale = existing.riskStale || !!d.risk_score_stale
        if (d.risk_score > existing.maxRiskScore) {
          existing.maxRisk = d.risk_level
          existing.maxRiskScore = d.risk_score
        }
        if (!existing.lastSeen || d.last_seen_at > existing.lastSeen) {
          existing.lastSeen = d.last_seen_at
        }
        d.source_types.forEach(s => existing.sources.add(s))
        userMap.set(user, existing)
      }
    }
  }

  const users = Array.from(userMap.entries())
    .map(([username, data]) => ({ username, ...data, sources: Array.from(data.sources) }))
    .sort((a, b) => b.maxRiskScore - a.maxRiskScore)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Identity signals</h1>
        <span className="text-sm text-slate-400">{users.length} identities in this sample</span>
      </div>

      <p className="text-xs text-slate-400 leading-relaxed">A bounded view of identities in up to 100 detections, ordered by impacted users. This is not a complete user inventory. Identity evidence supports incident review, not employee monitoring.</p>
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        <input
          aria-label="Search identities" type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search users..."
          className="w-full bg-surface-800 border border-surface-600/40 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-accent/50 placeholder-slate-600"
        />
      </div>

      {isLoading && <TableSkeleton rows={10} columns={5} />}
      {isError && <ErrorAlert onRetry={refetch} />}

      {!isLoading && !isError && users.length === 0 && (
        <EmptyState icon={Users} title="No user AI activity detected" description="AI activity will appear here once events are correlated with user identities." />
      )}

      {!isLoading && users.length > 0 && (
        <div className="bg-surface-800 border border-surface-600/30 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600/30 text-left text-xs text-slate-500 uppercase tracking-wider">
                <th className="px-4 py-3 font-medium">Username</th>
                <th className="px-4 py-3 font-medium">AI Tools</th>
                <th className="px-4 py-3 font-medium">Highest Risk</th>
                <th className="px-4 py-3 font-medium">Last Activity</th>
                <th className="px-4 py-3 font-medium">Sources</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.username} className="data-row">
                  <td className="px-4 py-3 font-medium font-mono text-slate-200">{u.username}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-slate-400">{u.tools.length} tool{u.tools.length > 1 ? 's' : ''}</span>
                    <span className="text-xs text-slate-600 ml-2 truncate max-w-[200px] inline-block align-bottom">
                      {u.tools.slice(0, 3).join(', ')}{u.tools.length > 3 ? ` +${u.tools.length - 3}` : ''}
                    </span>
                  </td>
                  <td className="px-4 py-3"><RiskBadge level={u.maxRisk} stale={u.riskStale} /></td>
                  <td className="px-4 py-3 text-xs text-slate-400">
                    {u.lastSeen ? formatDistanceToNow(new Date(u.lastSeen), { addSuffix: true }) : '—'}
                  </td>
                  <td className="px-4 py-3"><SourceIcons sources={u.sources} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
