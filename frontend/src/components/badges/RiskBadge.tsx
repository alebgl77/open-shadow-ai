import clsx from 'clsx'

const STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border border-red-500/30',
  high: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  low: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  info: 'bg-slate-500/15 text-slate-400 border border-slate-500/30',
}

interface Props {
  level: string
  score?: number
  showScore?: boolean
  stale?: boolean
}

export default function RiskBadge({ level, score, showScore = false, stale = false }: Props) {
  if (stale) return <span className="badge bg-amber-500/15 text-amber-300 border border-amber-500/30" title="The last calculated score may not reflect current governance. Review the evidence detail.">Needs recalculation</span>
  const normalized = level.toLowerCase()
  return (
    <span className={clsx('inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium', STYLES[normalized] || STYLES.info)}>
      {normalized === 'critical' && <span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-pulse" />}
      {normalized}
      {showScore && score !== undefined && <span className="font-mono opacity-70">({score})</span>}
    </span>
  )
}
