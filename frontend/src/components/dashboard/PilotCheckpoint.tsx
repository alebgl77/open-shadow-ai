import type { UseQueryResult } from '@tanstack/react-query'
import { ArrowRight, CircleDot, Database, Layers3 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { REVIEW_DISCOVERIES_PATH } from '@/api/detections'
import type { DashboardSummary, EvidenceSummary, SourceHealth } from '@/api/dashboard'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { useI18n } from '@/i18n'

interface Props {
  evidence: UseQueryResult<EvidenceSummary>
  sources: UseQueryResult<SourceHealth[]>
  summary: UseQueryResult<DashboardSummary>
}

const freshness = (source: SourceHealth) => !source.last_event
  ? 'No retained event'
  : source.status === 'active' ? 'Recent event' : 'Older event'

const timestampFormat: Intl.DateTimeFormatOptions = {
  year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
  timeZone: 'UTC', timeZoneName: 'short',
}

export default function PilotCheckpoint({ evidence, sources, summary }: Props) {
  const { tr, enumLabel, formatDate, formatNumber } = useI18n()
  const observed = evidence.data
  const sourceGroups = {
    'Recent event': 0,
    'Older event': 0,
    'No retained event': 0,
  }
  for (const source of sources.data ?? []) sourceGroups[freshness(source)]++

  return <section className="stat-card border-accent/20" aria-labelledby="pilot-checkpoint">
    <div className="mb-4">
      <h2 id="pilot-checkpoint" className="text-base font-medium">{tr('Pilot checkpoint')}</h2>
      <p className="mt-1 text-xs leading-relaxed text-slate-400">{tr('Check what your sources observed and which findings need review.')}</p>
    </div>
    <div className="grid gap-px overflow-hidden rounded-lg border border-surface-600/40 bg-surface-600/40 lg:grid-cols-3">
      <div className="min-w-0 bg-surface-950 p-4">
        <h3 className="flex items-center gap-2 text-sm font-medium"><Layers3 size={15} className="shrink-0 text-accent" aria-hidden="true"/>{tr('Observation window')}</h3>
        {evidence.isError ? <ErrorAlert message={tr('Evidence metrics unavailable')} onRetry={evidence.refetch}/> :
          !observed ? <p role="status" className="mt-3 text-xs text-slate-400">{tr('Loading evidence…')}</p> : <>
            <p className="mt-3 text-xs text-slate-400">
              <time dateTime={observed.window_start}>{formatDate(observed.window_start, timestampFormat)}</time>
              {' – '}
              <time dateTime={observed.window_end}>{formatDate(observed.window_end, timestampFormat)}</time>
            </p>
            {observed.total_events === 0 ? <p className="mt-2 text-sm text-slate-300">{tr('No events observed in this window.')}</p> : <>
              <p className="mt-2 text-sm text-slate-300">{tr('Observed events · {count}', { count: formatNumber(observed.total_events) })}</p>
              <p className="mt-2 text-xs text-slate-400">{tr('Model reporting · {share} ({reported} of {total} events)', {
                share: formatNumber(observed.measurement.model_known_events / observed.total_events, { style: 'percent' }),
                reported: formatNumber(observed.measurement.model_known_events),
                total: formatNumber(observed.total_events),
              })}</p>
            </>}
            <p className="mt-2 text-xs leading-relaxed text-slate-400">{tr('A domain observation can suggest a service. Model, token and cost reporting depends on the source.')}</p>
          </>}
      </div>
      <div className="flex min-w-0 flex-col bg-surface-950 p-4">
        <h3 className="flex items-center gap-2 text-sm font-medium"><Database size={15} className="shrink-0 text-accent" aria-hidden="true"/>{tr('Source types by last event')}</h3>
        {sources.isError ? <ErrorAlert message={tr('Source health is unavailable.')} onRetry={sources.refetch}/> :
          sources.isPending ? <p role="status" className="mt-3 text-xs text-slate-400">{tr('Checking sources…')}</p> :
          !sources.data?.length ? <p className="mt-3 text-sm text-slate-300">{tr('No source types returned.')}</p> : <>
            <p className="mt-2 text-xs text-slate-400">
              {tr('Source status checked')} · <time dateTime={new Date(sources.dataUpdatedAt).toISOString()}>{formatDate(sources.dataUpdatedAt, timestampFormat)}</time>
            </p>
            <dl className="mt-3 space-y-1.5 text-xs">
              <div className="flex justify-between gap-2"><dt className="text-slate-400">{tr('Recent · under one hour')}</dt><dd className="tabular-nums">{formatNumber(sourceGroups['Recent event'])}</dd></div>
              <div className="flex justify-between gap-2"><dt className="text-slate-400">{tr('Older')}</dt><dd className="tabular-nums">{formatNumber(sourceGroups['Older event'])}</dd></div>
              <div className="flex justify-between gap-2"><dt className="text-slate-400">{tr('No retained event')}</dt><dd className="tabular-nums">{formatNumber(sourceGroups['No retained event'])}</dd></div>
            </dl>
            <details className="mt-2 text-xs text-slate-400">
              <summary className="w-fit cursor-pointer rounded-sm hover:text-slate-200">{tr('Last event by source')}</summary>
              <ul className="mt-2 space-y-2">
                {sources.data.map(source => <li key={source.source_type} className="flex flex-wrap justify-between gap-x-2 gap-y-1 border-t border-surface-600/35 pt-2">
                  <span className="text-slate-300">{enumLabel(source.source_type)}</span>
                  {source.last_event
                    ? <span>{tr(freshness(source))} · <time dateTime={source.last_event}>{formatDate(source.last_event, timestampFormat)}</time></span>
                    : <span>{tr('No retained event')}</span>}
                </li>)}
              </ul>
            </details>
          </>}
        <p className="mt-2 text-xs leading-relaxed text-slate-400">{tr('Last event times describe retained observations. Collector health and unobserved coverage require separate checks.')}</p>
        <Link to="/sources" className="mt-auto inline-flex w-fit items-center gap-2 rounded-sm pt-3 text-xs font-medium text-accent hover:underline">
          {tr('Sources & coverage')} <ArrowRight size={13} aria-hidden="true"/>
        </Link>
      </div>
      <div className="flex min-w-0 flex-col bg-surface-950 p-4">
        <h3 className="flex items-center gap-2 text-sm font-medium"><CircleDot size={15} className="shrink-0 text-amber-300" aria-hidden="true"/>{tr('Awaiting review')}</h3>
        {summary.isError ? <ErrorAlert message={tr('Overview counts are unavailable.')} onRetry={summary.refetch}/> :
          !summary.data ? <p role="status" className="mt-3 text-xs text-slate-400">{tr('Loading review queue…')}</p> :
          <p className="mt-3 text-sm text-slate-300">{summary.data.unreviewed === 0
            ? tr('No new findings among retained detections.')
            : tr('New findings · {count}', { count: formatNumber(summary.data.unreviewed) })}</p>}
        <p className="mt-2 text-xs leading-relaxed text-slate-400">{tr('This count can include retained findings from outside the observation window.')}</p>
        <Link to={REVIEW_DISCOVERIES_PATH} className="mt-auto inline-flex w-fit items-center gap-2 rounded-sm pt-3 text-xs font-medium text-accent hover:underline">
          {tr('Open review queue')} <ArrowRight size={13} aria-hidden="true"/>
        </Link>
      </div>
    </div>
  </section>
}
