import { useI18n } from '@/i18n'
import { useEffect, useRef, useState } from 'react'
import { CancelledError, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { useAuthStore } from '@/stores/auth'
import { COLLECTOR_SOURCES, enrollCollector, getCollectorHealth, getCollectorRegistry, getPipelineHealth, revokeCollector, rotateCollector, type OnceCredential } from '@/api/operations'
import ErrorAlert from '@/components/ui/ErrorAlert'

type Action = { kind: 'enroll' } | { kind: 'rotate' | 'revoke'; id: string }

export default function CollectorOperations() {
  const { locale, tr, textLabel, enumLabel, formatDate, formatNumber } = useI18n()

  const when = (value: string | null | undefined) => formatDate(value)
  const count = (value: number | null | undefined) => value == null ? tr('Unknown') : formatNumber(value)
  const { mode, session, user } = useAuthStore()
  const role = user?.role
  const canRead = mode === 'live' && (role === 'analyst' || role === 'admin')
  const admin = mode === 'live' && role === 'admin'
  const queries = useQueryClient()
  const [offset, setOffset] = useState(0)
  const [action, setAction] = useState<Action | null>(null)
  const [secret, setSecret] = useState<OnceCredential | null>(null)
  const [pending, setPending] = useState(false)
  const [failure, setFailure] = useState('')
  const [sources, setSources] = useState<string[]>(['endpoint'])
  const [authority, setAuthority] = useState<'unknown' | 'verified' | 'denied'>('unknown')
  const authorityRef = useRef({ status: 'unknown' as 'unknown' | 'verified' | 'denied', epoch: 0 })
  const alive = useRef(true)
  const generation = useRef(0)
  const dialog = useRef<HTMLElement | null>(null)
  const returnFocus = useRef<HTMLElement | null>(null)
  const currentContext = () => {
    const current = useAuthStore.getState()
    return alive.current && current.mode === mode && current.session === session && current.user?.role === role
  }
  const confirmDenial = (error: unknown) => {
    if (!admin || !currentContext() || !isAxiosError(error) || ![401, 403].includes(error.response?.status || 0)) return
    const firstDenial = authorityRef.current.status !== 'denied'
    authorityRef.current = { status: 'denied', epoch: authorityRef.current.epoch + 1 }
    generation.current++
    setAuthority('denied'); setPending(false); setSecret(null); setAction(null)
    // The denial is independent of query objects. Cancellation/removal cannot
    // restore authority, and pending pre-denial responses lose their epoch.
    for (const prefix of ['collector-registry', 'pipeline-health', 'collector-health']) {
      void queries.cancelQueries({ queryKey: [prefix, mode, session, role] })
      if (firstDenial) queries.removeQueries({ queryKey: [prefix, mode, session, role] })
    }
  }
  const read = async <T,>(request: () => Promise<T>, managementProof = false): Promise<T> => {
    const epoch = authorityRef.current.epoch
    let data: T
    try { data = await request() } catch (error) { confirmDenial(error); throw error }
    if (!currentContext() || epoch !== authorityRef.current.epoch || (admin && !managementProof && authorityRef.current.status === 'denied')) throw new CancelledError({ silent: true })
    if (managementProof) {
      const restored = authorityRef.current.status === 'denied'
      authorityRef.current.status = 'verified'; setAuthority('verified')
      if (restored) void queries.invalidateQueries({ queryKey: ['collector-health', mode, session, role] })
    }
    return data
  }
  const health = useQuery({ queryKey: ['collector-health', mode, session, role, offset], queryFn: ({ signal }) => read(() => getCollectorHealth(offset, signal)), enabled: canRead && authority !== 'denied', refetchInterval: 30_000, retry: false })
  const registry = useQuery({ queryKey: ['collector-registry', mode, session, role, offset], queryFn: ({ signal }) => read(() => getCollectorRegistry(offset, signal), true), enabled: admin, refetchInterval: 30_000, retry: false })
  const pipeline = useQuery({ queryKey: ['pipeline-health', mode, session, role], queryFn: ({ signal }) => read(() => getPipelineHealth(signal)), enabled: admin && authority === 'verified', refetchInterval: 30_000, retry: false })
  const permissionDenied = authority === 'denied'
  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
      queries.removeQueries({ queryKey: ['collector-registry', mode, session, role] })
      queries.removeQueries({ queryKey: ['pipeline-health', mode, session, role] })
    }
  }, [mode, session, role, queries])
  // The parent keys this component on role/session. Check again after any await:
  // a credential returned to an old role/session must never become visible.
  const currentAdmin = () => {
    const current = useAuthStore.getState()
    return alive.current && authorityRef.current.status === 'verified' && current.mode === 'live' && current.session === session && current.user?.role === 'admin'
  }
  const close = () => { generation.current++; setPending(false); setSecret(null); setAction(null); setFailure(''); returnFocus.current?.focus() }
  const open = (next: Action) => { generation.current++; returnFocus.current = document.activeElement as HTMLElement; setSecret(null); setFailure(''); setSources(['endpoint']); setAction(next) }
  useEffect(() => {
    if (action) dialog.current?.querySelector<HTMLElement>('button, input, textarea')?.focus()
  }, [action, secret])
  const execute = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!action || !currentAdmin() || pending) return
    const ticket = generation.current
    const currentRequest = () => currentAdmin() && ticket === generation.current
    const fields = new FormData(event.currentTarget)
    setPending(true); setFailure(''); setSecret(null)
    try {
      let credential: OnceCredential | undefined
      if (action.kind === 'enroll') credential = await enrollCollector({ collector_id: String(fields.get('collector_id')), display_name: String(fields.get('display_name')), allowed_source_types: sources, expires_in_days: Number(fields.get('expires_in_days')) })
      else if (action.kind === 'rotate') credential = await rotateCollector(action.id, { overlap_seconds: Number(fields.get('overlap_seconds')), expires_in_days: Number(fields.get('expires_in_days')) })
      else await revokeCollector(action.id)
      if (!currentRequest()) return
      if (credential) setSecret({ api_key: credential.api_key, expires_at: credential.expires_at, previous_valid_until: credential.previous_valid_until })
      else setAction(null)
      void queries.invalidateQueries({ queryKey: ['collector-health'] })
      void queries.invalidateQueries({ queryKey: ['collector-registry'] })
    } catch (error) {
      confirmDenial(error)
      if (currentRequest()) setFailure('The action could not be confirmed. Refresh the registry before retrying; a lost response may follow a completed change. No credential has been retained.')
    } finally { if (currentRequest()) setPending(false) }
  }
  if (mode === 'demo') return <div className="stat-card text-sm text-slate-400">{tr("Simulation only. Live collector administration and deployment queues are unavailable in the demo.")}</div>
  if (!canRead) return <div role="status" className="stat-card text-sm text-slate-400">{tr("Collector operational health requires an analyst or administrator role.")}</div>
  const managementAvailable = admin && authority === 'verified' && !registry.isError && !!registry.data
  return <>
    <section aria-label={tr("Enrolled collectors")} className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-lg font-semibold">{tr("Enrolled collectors")}</h2><p className="text-xs text-slate-400 mt-1">{tr("Server contacts and original observations are separate. Client counters are advisory. Capture loss is unknown.")}</p></div>{managementAvailable && <button className="primary-button" disabled={pending} onClick={() => open({ kind: 'enroll' })}>{tr("Enroll collector")}</button>}</div>
      {admin && permissionDenied ? <div><ErrorAlert message={tr("Collector administration is unavailable. Access was denied; cached data and credentials have been discarded.")}/><button className="secondary-button" onClick={() => void registry.refetch()}>{tr("Refresh administration access")}</button></div> : admin && registry.isError && <ErrorAlert message={tr("Collector administration is unavailable. No cached privileged registry is displayed.")} onRetry={() => void registry.refetch()} />}
      {permissionDenied ? <p className="text-sm text-slate-400">{tr("Collector health requires a new authorized refresh.")}</p> : health.isError ? <ErrorAlert message={tr("Collector health is unavailable. Current status and queue counts cannot be confirmed.")} onRetry={() => void health.refetch()} /> : health.isPending ? <p className="text-sm text-slate-400">{tr("Loading collector health…")}</p> : health.data && <>
        {!health.data.items.length && <p className="stat-card text-sm text-slate-400">{tr("No enrolled collectors in this workspace.")}</p>}
        <div className="grid xl:grid-cols-2 gap-4">{health.data.items.map(collector => {
          const registered = registry.data?.items.find(item => item.collector_id === collector.collector_id)
          const revoked = collector.status === 'revoked' || registered?.is_active === false
          const reported = collector.client_reported
          return <article key={collector.collector_id} className="stat-card">
            <div className="flex items-start justify-between gap-3"><div><h3 className="font-medium">{collector.display_name}</h3><p className="text-xs font-mono text-slate-500 mt-1 break-all">{collector.collector_id}</p></div><span className="badge bg-surface-700 text-slate-300">{enumLabel(revoked ? 'revoked' : collector.status)}</span></div>
            <p className="text-xs text-slate-400 my-3">{tr("Allowed sources:")} {collector.allowed_source_types.map(enumLabel).join(', ')}</p>
            <dl className="text-xs space-y-2"><div><dt className="text-slate-500">{tr("Last server contact")}</dt><dd>{when(collector.last_server_contact_at)}</dd></div><div><dt className="text-slate-500">{tr("Last heartbeat received")}</dt><dd>{when(collector.last_heartbeat_at)}</dd></div><div><dt className="text-slate-500">{tr("Original last observation")}</dt><dd>{when(collector.last_observed_at)}</dd></div></dl>
            {collector.status === 'quiet' && <p className="text-xs text-slate-400 mt-3">{tr("The collector contacted the server recently; new evidence has not been observed recently. A quiet source or replay can cause this.")}</p>}
            <div className="border-t border-surface-600/30 mt-4 pt-3 text-xs"><p className="text-slate-400">{tr("Client reported ·")} {reported.fresh ? tr("recent heartbeat") : tr("stale or missing heartbeat")} · {when(reported.as_of)}</p><dl className="grid sm:grid-cols-2 gap-2 mt-3"><div><dt className="text-slate-500">{tr("Queued events")}</dt><dd>{count(reported.queue_events)}</dd></div><div><dt className="text-slate-500">{tr("Queued bytes")}</dt><dd>{count(reported.queued_bytes)}</dd></div><div><dt className="text-slate-500">{tr("Dropped / expired / rejected events")}</dt><dd>{count(reported.dropped_events)} / {count(reported.expired_events)} / {count(reported.rejected_events)}</dd></div><div><dt className="text-slate-500">{tr("Client last success")}</dt><dd>{when(reported.last_success_at)}</dd></div></dl></div>
            {managementAvailable && <div className="flex gap-3 mt-4"><button className="secondary-button" disabled={!registered || revoked || pending} onClick={() => open({ kind: 'rotate', id: collector.collector_id })}>{tr('Rotate key for {id}', { id: collector.collector_id })}</button><button className="secondary-button text-red-300" disabled={!registered || revoked || pending} onClick={() => open({ kind: 'revoke', id: collector.collector_id })}>{tr('Revoke {id}', { id: collector.collector_id })}</button></div>}
          </article>
        })}</div>
        <div className="flex items-center justify-between text-xs text-slate-400"><span>{tr('{count} enrolled collectors · checked {time}', { count: formatNumber(health.data.total), time: when(health.data.as_of) })}</span><div className="flex gap-2"><button className="secondary-button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>{tr("Previous collectors")}</button><button className="secondary-button" disabled={offset + 50 >= health.data.total} onClick={() => setOffset(offset + 50)}>{tr("Next collectors")}</button></div></div>
      </>}
    </section>
    {admin && <section aria-label={tr("Deployment pipeline")} className="space-y-4"><h2 className="text-lg font-semibold">{tr("Deployment pipeline")}</h2><p className="text-xs text-slate-400">{tr("Installation-wide queues, visible to administrators. Retained entries include acknowledged records or replay sources and are not ready backlog. Unknown lag stays unknown.")}</p>
      {authority !== 'verified' || pipeline.isError || pipeline.data?.backend_available === false ? <ErrorAlert message={tr("Deployment queue state is unavailable. Redis status and worker progress cannot be confirmed.")} onRetry={permissionDenied ? undefined : () => void pipeline.refetch()} /> : pipeline.isPending ? <p className="text-sm text-slate-400">{tr("Loading deployment queues…")}</p> : pipeline.data?.stages.map(stage => <article key={stage.stage} className="stat-card overflow-x-auto"><div className="flex flex-wrap justify-between gap-2 mb-4"><h3 className="capitalize font-medium">{enumLabel(stage.stage)} · {enumLabel(stage.status)}</h3><span className="text-xs text-slate-400">{tr("Retained dead-letter pointers:")} {count(stage.deadletter_retained)}</span></div><table className="w-full text-xs"><thead><tr className="text-slate-500 text-left"><th className="pb-3 pr-4">{tr("Stream / state")}</th><th className="pr-4">{tr("Pending ACK")}</th><th className="pr-4">{tr("Undelivered")}</th><th className="pr-4">{tr("Retained entries")}</th><th>{tr("Worker progress")}</th></tr></thead><tbody>{stage.streams.map(stream => <tr key={stream.stream} className="border-t border-surface-600/30"><td className="py-3 pr-4 font-mono">{stream.stream}<span className="block text-slate-500 font-sans">{enumLabel(stream.status)}</span></td><td>{count(stream.pending)}</td><td>{count(stream.undelivered)}</td><td>{count(stream.retained_entries)}</td><td className="py-3"><p>{tr("Last ACK / DLQ:")} {when(stream.last_progress_at)}</p><p className="text-slate-500">{tr("Poll:")} {when(stream.last_poll_at)}{tr("· worker state")} {stream.worker_state_fresh ? tr('Recent') : tr("stale or missing")}</p><p className="text-slate-500">{tr("ACK")} {count(stream.counters.acknowledged)}{tr("· retries")} {count(stream.counters.retryable_failures)}{tr("· rejected attempts")} {count(stream.counters.rejected_attempts)}{tr("· DLQ")} {count(stream.counters.deadlettered)}{tr("· replays")} {count(stream.counters.replayed)}</p><p className="text-slate-500">{tr("Counter epoch:")} {when(stream.counters_since)}{tr("· oldest pending")} {stream.oldest_pending_age_seconds == null ? tr('Unknown') : tr('{count} seconds', { count: formatNumber(Math.floor(stream.oldest_pending_age_seconds)) })}</p></td></tr>)}</tbody></table></article>)}
    </section>}
    {managementAvailable && action && <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"><section ref={dialog} role="dialog" aria-modal="true" aria-label={secret ? tr("One-time collector key") : tr(action.kind === 'enroll' ? 'Enroll collector dialog' : action.kind === 'rotate' ? 'Rotate collector dialog' : 'Revoke collector dialog')} onKeyDown={event => {
      if (event.key === 'Escape') { event.preventDefault(); close() }
      if (event.key === 'Tab') {
        const nodes = dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), textarea, [tabindex="0"]')
        if (nodes?.length && ((event.shiftKey && document.activeElement === nodes[0]) || (!event.shiftKey && document.activeElement === nodes[nodes.length - 1]))) { event.preventDefault(); nodes[event.shiftKey ? nodes.length - 1 : 0].focus() }
      }
    }} className="stat-card w-full max-w-xl max-h-[90vh] overflow-y-auto"><div className="flex items-center justify-between gap-4"><h2 className="text-lg font-semibold">{secret ? tr("Save this one-time collector key") : action.kind === 'enroll' ? tr("Enroll a collector") : tr(action.kind === 'rotate' ? 'Rotate key for {id}' : 'Revoke {id}', { id: action.id })}</h2><button aria-label={tr("Close credential dialog")} className="secondary-button" onClick={close}>{tr("Close")}</button></div>
      {secret ? <div className="space-y-4 mt-4"><p className="text-sm text-slate-400">{tr("Copy this key to the collector's private key file now. It will disappear when you close this dialog and cannot be retrieved again.")}</p><label className="block text-xs">{tr("One-time API key")}<textarea className="field w-full mt-2 font-mono break-all" readOnly autoComplete="off" value={secret.api_key} rows={3}/></label><p className="text-xs text-slate-400">{tr("Expires:")} {when(secret.expires_at)}</p>{secret.previous_valid_until && <p className="text-xs text-slate-400">{tr("Existing keys overlap until:")} {when(secret.previous_valid_until)}</p>}</div> : <form onSubmit={event => void execute(event)} className="space-y-4 mt-4">
        {action.kind === 'enroll' && <><label className="block text-xs">{tr("Collector ID")}<input className="field w-full mt-2" name="collector_id" required maxLength={255} pattern="[A-Za-z0-9][A-Za-z0-9_.:-]*" autoComplete="off" /></label><label className="block text-xs">{tr("Display name")}<input className="field w-full mt-2" name="display_name" required maxLength={255}/></label><fieldset><legend className="text-xs mb-2">{tr("Allowed sources")}</legend><div className="grid grid-cols-3 gap-2">{COLLECTOR_SOURCES.map(source => <label key={source} className="flex items-center gap-2 text-xs"><input type="checkbox" checked={sources.includes(source)} onChange={event => setSources(current => event.target.checked ? [...current, source] : current.filter(value => value !== source))}/>{locale === 'en' ? source : enumLabel(source)}</label>)}</div></fieldset></>}
        {action.kind !== 'revoke' && <label className="block text-xs">{tr("Key validity (days)")}<input className="field w-full mt-2" type="number" name="expires_in_days" min={1} max={365} defaultValue={365} required /></label>}
        {action.kind === 'rotate' && <label className="block text-xs">{tr("Existing key overlap (seconds)")}<input className="field w-full mt-2" type="number" name="overlap_seconds" min={0} max={86400} defaultValue={3600} required /></label>}
        {action.kind === 'revoke' && <p className="text-sm text-red-300">{tr("Revocation disables this identity and all its keys. Enroll a new collector identity to resume delivery.")}</p>}
        {failure && <p role="alert" className="text-sm text-red-300">{textLabel(failure)}</p>}
        <button type="submit" className="primary-button" disabled={pending || (action.kind === 'enroll' && !sources.length)}>{pending ? tr("Submitting…") : action.kind === 'enroll' ? tr("Create collector and key") : action.kind === 'rotate' ? tr("Issue replacement key") : tr("Confirm revocation")}</button>
      </form>}
    </section></div>}
  </>
}
