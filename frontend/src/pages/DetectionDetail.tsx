import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Users, Monitor, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import { getDetection, updateDetection, getDetectionTimeline } from '@/api/detections'
import RiskBadge from '@/components/badges/RiskBadge'
import ApprovalBadge from '@/components/badges/ApprovalBadge'
import ConfidenceBadge from '@/components/badges/ConfidenceBadge'
import ClassificationBadge from '@/components/badges/ClassificationBadge'
import EntityTypeBadge from '@/components/badges/EntityTypeBadge'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { DetailSkeleton } from '@/components/ui/LoadingSkeleton'
import clsx from 'clsx'
import { formatDistanceToNow, format } from 'date-fns'
import { useAuthStore } from '@/stores/auth'
import { NETWORK_NOTICE, NETWORK_PROTOCOLS, networkEndpoint } from '@/api/network'
import { sourceLabel } from '@/components/ui/SourceIcons'

function CopyableId({ id }: { id: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={async () => { try { await navigator.clipboard.writeText(id); setCopied(true); setTimeout(() => setCopied(false), 2000) } catch { setCopied(false) } }}
      className="flex items-center gap-1 text-xs font-mono text-slate-500 hover:text-slate-300 transition-colors"
      title="Copy detection ID"
    >
      {id.slice(0, 8)}...
      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
    </button>
  )
}

function NetworkEvidence({ data }: { data: Record<string, unknown> }) {
  const canInspect = useAuthStore(s => s.user?.role === 'analyst' || s.user?.role === 'admin')
  const observations = Array.isArray(data.network_observations)
    ? data.network_observations.filter((value): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value)).slice(0, 10) : []
  const protocols = data.protocol_counts && typeof data.protocol_counts === 'object' && !Array.isArray(data.protocol_counts)
    ? data.protocol_counts as Record<string, unknown> : {}
  const text = (value: unknown) => typeof value === 'string' ? value : 'Not observed'
  return <section aria-label="Network evidence" className="space-y-3 border-t border-surface-600/30 pt-3 mt-3">
    <p className="font-sans text-slate-400 leading-relaxed">{NETWORK_NOTICE} DNS is weaker evidence; repeats and additional protocols do not create independent sources.</p>
    <dl className="flex flex-wrap gap-3">{NETWORK_PROTOCOLS.map(protocol => typeof protocols[protocol] === 'number' && Number.isFinite(protocols[protocol]) ? <div key={protocol} className="flex gap-2"><dt>{protocol}</dt><dd>{String(protocols[protocol])}</dd></div> : null)}</dl>
    {canInspect ? <><p className="text-slate-500">Retained sample: up to 10 observations.</p>
    {observations.map((observation, index) => <div key={index} className="rounded bg-surface-800 p-3 space-y-2 break-words">
      <p className="text-slate-200">{text(observation.protocol)} · {text(observation.domain)}</p>
      <p className="text-slate-500">{text(observation.timestamp)}</p>
      <dl className="grid sm:grid-cols-2 gap-2"><div><dt className="text-slate-500">Source address</dt><dd className="break-all">{text(observation.src_ip)}</dd></div><div><dt className="text-slate-500">Destination</dt><dd className="break-all">{networkEndpoint(typeof observation.dst_ip === 'string' ? observation.dst_ip : null, typeof observation.dst_port === 'number' ? observation.dst_port : null)}</dd></div><div><dt className="text-slate-500">Sensor</dt><dd className="break-all">{text(observation.collector_id)}</dd></div></dl>
      <details><summary className="cursor-pointer text-accent">Observation identity</summary><p className="mt-2 break-all">{text(observation.event_id)}</p></details>
    </div>)}
    {!observations.length && <p className="text-slate-500">No structured network sample retained.</p>}
    <Link to="/network" className="inline-flex text-accent font-sans">Inspect network observations</Link></> : <p className="text-slate-500">Detailed network observations are available to analysts and administrators.</p>}
  </section>
}

function EvidenceSection({ source, data }: { source: string; data: Record<string, unknown> }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="border border-surface-600/20 rounded-lg overflow-hidden">
      <button onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2.5 bg-surface-700/30 hover:bg-surface-700/50 transition-colors">
        <div className="flex items-center gap-2">
          {open ? <ChevronDown className="w-3.5 h-3.5 text-slate-400" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-400" />}
          <span className="text-xs font-mono text-accent font-medium uppercase">{sourceLabel(source)}</span>
          <span className="text-xs text-slate-500">{String(data.event_count ?? 0)} events</span>
        </div>
        <span className="text-[10px] text-slate-600 font-mono">confidence: {String(data.confidence_base ?? '—')}</span>
      </button>
      {open && (
        <div className="p-4 bg-surface-900/50 space-y-2 text-xs font-mono text-slate-300">
          <div className="grid grid-cols-2 gap-2">
            <div><span className="text-slate-500">First seen:</span> {String(data.first_seen ?? '—')}</div>
            <div><span className="text-slate-500">Last seen:</span> {String(data.last_seen ?? '—')}</div>
            <div><span className="text-slate-500">Matched on:</span> {String(data.matched_field ?? '—')}</div>
            <div><span className="text-slate-500">Events:</span> {String(data.event_count ?? 0)}</div>
          </div>
          {Array.isArray(data.sample_values) && data.sample_values.length > 0 && (
            <div>
              <span className="text-slate-500">Sample values:</span>
              <div className="mt-1 space-y-0.5">
                {data.sample_values.filter((value): value is string => typeof value === 'string').map((v, i) => (
                  <div key={i} className="bg-surface-800 px-2 py-1 rounded text-slate-300">{v}</div>
                ))}
              </div>
            </div>
          )}
          {source === 'network' && <NetworkEvidence data={data} />}
        </div>
      )}
    </div>
  )
}

export default function DetectionDetail() {
  const { id } = useParams<{ id: string }>()
  const queryClient = useQueryClient()
  const [note, setNote] = useState('')
  const canEdit = useAuthStore(s => s.user?.role !== 'viewer')
  const mode = useAuthStore(s => s.mode)
  const session = useAuthStore(s => s.session)

  const { data: detection, isLoading, isError, refetch } = useQuery({
    queryKey: ['detection', id, mode, session],
    queryFn: () => getDetection(id!),
    enabled: !!id,
  })

  const { data: timeline } = useQuery({
    queryKey: ['timeline', id, mode, session],
    queryFn: () => getDetectionTimeline(id!),
    enabled: !!id,
  })

  const mutation = useMutation({
    mutationFn: (body: Parameters<typeof updateDetection>[1]) => updateDetection(id!, body),
    onSuccess: (_, body) => { if (body.analyst_notes !== undefined) setNote(''); queryClient.invalidateQueries() },
  })

  if (isLoading) return <DetailSkeleton />
  if (isError) return <ErrorAlert message="Failed to load detection" onRetry={refetch} />
  if (!detection) return <ErrorAlert message="Detection not found" />

  const bundle = (detection.evidence_bundle || {}) as Record<string, unknown>
  const confFactors = (bundle?.confidence_factors as Array<{ factor: string; value: number; description: string }>) ?? []
  const riskFactors = (bundle?.risk_factors as Array<{ factor: string; value: number; description: string }>) ?? []

  // Extract evidence sources (exclude internal keys)
  const evidenceSources = Object.entries(bundle).filter(
    ([k, value]) => !k.startsWith('_') && !['confidence_factors', 'risk_factors'].includes(k) && !!value && typeof value === 'object' && !Array.isArray(value)
  )

  return (
    <div className="space-y-6">
      {/* Critical alert */}
      {!detection.risk_score_stale && detection.risk_level === 'critical' && detection.analyst_status === 'new' && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 flex items-center gap-2 text-red-400 text-sm">
          <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
          Critical risk — unreviewed detection requires immediate attention
        </div>
      )}

      {detection.risk_score_stale && <div role="status" className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"><strong>Risk score needs recalculation.</strong> An approval may have expired, or the retained evidence lacks factors needed to recalculate this score. The breakdown below is the last computed result, not a current assessment. Review the policy and refresh source evidence before relying on it.</div>}
      <div>
        <Link to="/discoveries" className="flex items-center gap-1 text-sm text-slate-400 hover:text-accent mb-3 transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Discoveries
        </Link>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold">{detection.entity_name}</h1>
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              <EntityTypeBadge entityType={detection.entity_type} />
              <ClassificationBadge classification={detection.classification} /><ApprovalBadge status={detection.governance_status} />
              <RiskBadge stale={detection.risk_score_stale} level={detection.risk_level} score={detection.risk_score} showScore />
              <ConfidenceBadge level={detection.confidence_level} score={detection.confidence_score} showScore />
            </div>
          </div>
          <div className="text-right space-y-1">
            <CopyableId id={detection.detection_id} />
            <p className="text-xs text-slate-500">First seen {formatDistanceToNow(new Date(detection.first_seen_at), { addSuffix: true })}</p>
            <p className="text-xs text-slate-500">{detection.total_events_count.toLocaleString()} total events</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Evidence accordion */}
          <div className="stat-card">
            <h3 className="text-sm font-medium text-slate-400 mb-4">Evidence by Source</h3>
            <div className="space-y-2">
              {evidenceSources.map(([source, data]) => (
                <EvidenceSection key={source} source={source} data={data as Record<string, unknown>} />
              ))}
              {evidenceSources.length === 0 && (
                <p className="text-sm text-slate-500 text-center py-4">No evidence available</p>
              )}
            </div>
          </div>

          {/* Scoring breakdown */}
          <div className="stat-card">
            <h3 className="text-sm font-medium text-slate-400 mb-4">Scoring Breakdown</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-xs text-slate-500 mb-3">
                  Confidence: <span className="text-accent font-mono font-medium">{detection.confidence_score.toFixed(2)}</span>
                </p>
                <div className="space-y-2">
                  {confFactors.map((f, i) => (
                    <div key={i} className="flex items-center justify-between text-xs bg-surface-900/50 rounded px-3 py-1.5">
                      <span className="text-slate-400">{f.description}</span>
                      <span className={clsx('font-mono font-medium', f.value >= 0 ? 'text-emerald-400' : 'text-red-400')}>
                        {f.value >= 0 ? '+' : ''}{typeof f.value === 'number' ? f.value.toFixed(2) : f.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs text-slate-500 mb-3">
                  {detection.risk_score_stale ? 'Last computed risk (stale)' : 'Risk'}: <span className="text-amber-400 font-mono font-medium">{detection.risk_score}</span>
                </p>
                <div className="space-y-2">
                  {riskFactors.map((f, i) => (
                    <div key={i} className="flex items-center justify-between text-xs bg-surface-900/50 rounded px-3 py-1.5">
                      <span className="text-slate-400">{f.description}</span>
                      <span className={clsx('font-mono font-medium', f.value > 0 ? 'text-red-400' : 'text-emerald-400')}>
                        {f.value >= 0 ? '+' : ''}{f.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Timeline */}
          {timeline && timeline.length > 0 && (
            <div className="stat-card">
              <h3 className="text-sm font-medium text-slate-400 mb-4">Timeline</h3>
              <div className="relative pl-6 space-y-4">
                <div className="absolute left-[9px] top-2 bottom-2 w-px bg-surface-600/50" />
                {timeline.map((entry, i) => (
                  <div key={i} className="relative flex items-start gap-3">
                    <div className={clsx(
                      'absolute left-[-15px] w-[7px] h-[7px] rounded-full mt-1.5 ring-2 ring-surface-800',
                      entry.type === 'first_seen' ? 'bg-emerald-500' :
                      entry.type === 'last_seen' ? 'bg-blue-500' : 'bg-accent'
                    )} />
                    <div>
                      <p className="text-sm text-slate-200">{entry.description}</p>
                      <p className="text-[11px] text-slate-500 font-mono">{format(new Date(entry.timestamp), 'MMM d, yyyy HH:mm')}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Impact stats */}
          <div className="grid grid-cols-2 gap-4">
            <div className="stat-card flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-accent/10 flex items-center justify-center">
                <Users className="w-5 h-5 text-accent" />
              </div>
              <div>
                <p className="text-2xl font-bold font-mono">{detection.impacted_users_count}</p>
                <p className="text-xs text-slate-400">Observed identities</p>
              </div>
            </div>
            <div className="stat-card flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-accent/10 flex items-center justify-center">
                <Monitor className="w-5 h-5 text-accent" />
              </div>
              <div>
                <p className="text-2xl font-bold font-mono">{detection.impacted_devices_count}</p>
                <p className="text-xs text-slate-400">Observed devices</p>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Analyst actions */}
          <div className="stat-card">
            <h3 className="text-sm font-medium text-slate-400 mb-4">Analyst Actions</h3>
            <div className="space-y-3">
              <div>
                <label htmlFor="review-classification" className="text-xs text-slate-500 mb-1 block">Classification</label>
                <select id="review-classification" aria-label="Classification" disabled={!canEdit || mutation.isPending} value={detection.classification} onChange={(e) => mutation.mutate({ classification: e.target.value })}
                  className="w-full bg-surface-900 border border-surface-600 rounded-lg px-3 py-2 text-sm focus:border-accent/50 focus:outline-none">
                  <option value="unknown">Unknown</option>
                  <option value="unsanctioned">Unsanctioned</option>
                  <option value="tolerated">Tolerated</option>
                  <option value="sanctioned">Sanctioned</option>
                </select>
              </div>
              <div>
                <label htmlFor="review-status" className="text-xs text-slate-500 mb-1 block">Status</label>
                <select id="review-status" aria-label="Review status" disabled={!canEdit || mutation.isPending} value={detection.analyst_status} onChange={(e) => mutation.mutate({ analyst_status: e.target.value })}
                  className="w-full bg-surface-900 border border-surface-600 rounded-lg px-3 py-2 text-sm focus:border-accent/50 focus:outline-none">
                  <option value="new">New</option>
                  <option value="investigating">Investigating</option>
                  <option value="classified">Classified</option>
                  <option value="false_positive">False Positive</option>
                  <option value="escalated">Escalated</option>
                </select>
              </div>
              <div>
                <label htmlFor="review-note" className="text-xs text-slate-500 mb-1 block">Add Note</label>
                <textarea id="review-note" aria-label="Analyst note" disabled={!canEdit || mutation.isPending} value={note} onChange={(e) => setNote(e.target.value)}
                  className="w-full bg-surface-900 border border-surface-600 rounded-lg px-3 py-2 text-sm h-20 resize-none focus:border-accent/50 focus:outline-none"
                  placeholder="Write a note..." />
                <button onClick={() => mutation.mutate({ analyst_notes: note })} disabled={!canEdit || !note.trim() || mutation.isPending}
                  className="mt-2 w-full bg-accent/20 text-accent border border-accent/30 rounded-lg py-1.5 text-sm hover:bg-accent/30 disabled:opacity-50 transition-colors">
                  {mutation.isPending ? 'Saving...' : 'Save Note'}
                </button>
                {mutation.isError && <p role="alert" className="text-xs text-red-300 mt-2">Save failed. Your note has been kept. Try again.</p>}
                {mutation.isSuccess && <p role="status" className="text-xs text-accent mt-2">Review saved.</p>}
                {!canEdit && <p className="text-xs text-slate-400 mt-2">Your viewer role has read-only access.</p>}
              </div>
            </div>
          </div>

          {/* Metadata */}
          <div className="stat-card">
            <h3 className="text-sm font-medium text-slate-400 mb-3">Metadata</h3>
            <div className="space-y-2 text-xs">
              {[
                ['Detection ID', detection.detection_id],
                ['Created', format(new Date(detection.created_at), 'MMM d, yyyy HH:mm')],
                ['Updated', format(new Date(detection.updated_at), 'MMM d, yyyy HH:mm')],
                ['First seen', format(new Date(detection.first_seen_at), 'MMM d, yyyy HH:mm')],
                ['Last seen', format(new Date(detection.last_seen_at), 'MMM d, yyyy HH:mm')],
                ['Reviewed at', detection.reviewed_at ? format(new Date(detection.reviewed_at), 'MMM d, yyyy HH:mm') : '—'],
                ['Catalog ID', detection.catalog_item_id || '—'],
              ].map(([label, value]) => (
                <div key={label} className="flex justify-between">
                  <span className="text-slate-500">{label}</span>
                  <span className="font-mono text-slate-300 truncate max-w-[180px] text-right">{value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Notes history */}
          {detection.analyst_notes && (
            <div className="stat-card">
              <h3 className="text-sm font-medium text-slate-400 mb-3">Notes History</h3>
              <pre className="text-xs text-slate-300 whitespace-pre-wrap font-mono leading-relaxed">{detection.analyst_notes}</pre>
            </div>
          )}

          {/* Reasoning */}
          {detection.reasoning_summary && (
            <div className="stat-card">
              <h3 className="text-sm font-medium text-slate-400 mb-3">Detection rationale</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{detection.reasoning_summary}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
