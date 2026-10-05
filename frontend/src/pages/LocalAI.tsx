import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Cpu } from 'lucide-react'
import { listDetections } from '@/api/detections'
import RiskBadge from '@/components/badges/RiskBadge'
import ClassificationBadge from '@/components/badges/ClassificationBadge'
import StatusBadge from '@/components/badges/StatusBadge'
import EntityTypeBadge from '@/components/badges/EntityTypeBadge'
import EmptyState from '@/components/ui/EmptyState'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { TableSkeleton } from '@/components/ui/LoadingSkeleton'

export default function LocalAI() {
  const navigate = useNavigate()

  // Fetch both local_runtime and local_container
  const { data: runtimes, isLoading: l1, isError: e1, refetch: r1 } = useQuery({
    queryKey: ['detections', 'local_runtime'],
    queryFn: () => listDetections({ entity_type: 'local_runtime', page_size: 100 }),
  })

  const { data: containers, isLoading: l2, isError: e2, refetch: r2 } = useQuery({
    queryKey: ['detections', 'local_container'],
    queryFn: () => listDetections({ entity_type: 'local_container', page_size: 100 }),
  })

  const isLoading = l1 || l2
  const isError = e1 || e2
  const items = [...(runtimes?.items || []), ...(containers?.items || [])]
    .sort((a, b) => b.risk_score - a.risk_score)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Cpu className="w-6 h-6 text-accent" />
          <h1 className="text-2xl font-bold tracking-tight">Local AI Runtimes</h1>
        </div>
        <span className="text-sm text-slate-400">{(runtimes?.total ?? 0) + (containers?.total ?? 0)} tool{items.length !== 1 ? 's' : ''}</span>
      </div>

      <p className="text-xs text-slate-400">Showing up to 100 runtimes and 100 containers. <Link to="/discoveries" className="text-accent">Open Discoveries</Link> to filter and page through all records. Unmanaged devices are outside endpoint coverage.</p>{isLoading && <TableSkeleton rows={6} columns={7} />}
      {isError && <ErrorAlert onRetry={() => { r1(); r2() }} />}

      {!isLoading && !isError && items.length === 0 && (
        <EmptyState
          icon={Cpu}
          title="No local AI runtimes detected"
          description="Deploy the endpoint agent on devices to discover Ollama, LM Studio, vLLM, and other local AI runtimes."
        />
      )}

      {!isLoading && items.length > 0 && (
        <div className="bg-surface-800 border border-surface-600/30 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600/30 text-left text-xs text-slate-500 uppercase tracking-wider">
                <th className="px-4 py-3 font-medium">Tool</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Devices</th>
                <th className="px-4 py-3 font-medium">Users</th>
                <th className="px-4 py-3 font-medium">Port</th>
                <th className="px-4 py-3 font-medium">Classification</th>
                <th className="px-4 py-3 font-medium">Risk</th>
                <th className="px-4 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map((d) => {
                const endpointEv = (d.evidence_bundle as Record<string, any>)?.endpoint
                const port = endpointEv?.sample_values?.find((v: string) => /^\d+$/.test(v)) || '—'
                return (
                  <tr
                    key={d.detection_id}
                    className="data-row cursor-pointer"
                    onClick={() => navigate(`/discoveries/${d.detection_id}`)}
                  >
                    <td className="px-4 py-3 font-medium text-slate-200"><button className="font-medium text-left hover:text-accent">{d.entity_name}</button></td>
                    <td className="px-4 py-3"><EntityTypeBadge entityType={d.entity_type} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{d.impacted_devices_count}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{d.impacted_users_count}</td>
                    <td className="px-4 py-3 font-mono text-xs text-accent">{port}</td>
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
