import { useI18n } from '@/i18n'
import clsx from 'clsx'

const STYLES: Record<string, string> = {
  new: 'bg-blue-500/15 text-blue-400',
  investigating: 'bg-yellow-500/15 text-yellow-400',
  classified: 'bg-emerald-500/15 text-emerald-400',
  false_positive: 'bg-slate-500/15 text-slate-500 line-through',
  escalated: 'bg-red-500/15 text-red-400',
}

interface Props {
  status: string
}

export default function StatusBadge({ status }: Props) {
  const { enumLabel } = useI18n()

  const normalized = status.toLowerCase()
  return (
    <span className={clsx('inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium', STYLES[normalized] || STYLES.new)}>
      {normalized === 'new' && <span className="w-1.5 h-1.5 bg-blue-400 rounded-full" />}
      {enumLabel(normalized)}
    </span>
  )
}
