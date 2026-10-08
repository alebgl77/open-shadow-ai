import { useI18n } from '@/i18n'
import clsx from 'clsx'

const STYLES: Record<string, string> = {
  very_high: 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30',
  high: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
  medium: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
  low: 'bg-slate-600/15 text-slate-500 border border-slate-600/30',
}

interface Props {
  level: string
  score?: number
  showScore?: boolean
}

export default function ConfidenceBadge({ level, score, showScore = false }: Props) {
  const { enumLabel, formatNumber } = useI18n()

  const normalized = level.toLowerCase()
  return (
    <span className={clsx('inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium', STYLES[normalized] || STYLES.low)}>
      {enumLabel(normalized)}
      {showScore && score !== undefined && <span className="font-mono opacity-70">{formatNumber(score, { minimumFractionDigits: 2, maximumFractionDigits: 2, useGrouping: false })}</span>}
    </span>
  )
}
