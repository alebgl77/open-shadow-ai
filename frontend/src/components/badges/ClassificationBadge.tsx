import clsx from 'clsx'

const STYLES: Record<string, string> = {
  sanctioned: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  tolerated: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  unsanctioned: 'bg-red-500/15 text-red-400 border border-red-500/30',
  unknown: 'bg-slate-500/15 text-slate-400 border border-slate-500/30',
}

interface Props {
  classification: string
}

export default function ClassificationBadge({ classification }: Props) {
  const normalized = classification.toLowerCase()
  return (
    <span className={clsx('inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium', STYLES[normalized] || STYLES.unknown)}>
      {normalized}
    </span>
  )
}
