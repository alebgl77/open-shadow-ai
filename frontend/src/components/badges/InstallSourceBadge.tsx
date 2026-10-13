import { useI18n } from '@/i18n'
import type { MessageKey } from '@/i18n/messages'
import clsx from 'clsx'

// The eight agent-reportable install sources plus '' for a record that carried none (wire v1).
const STYLES: Record<string, string> = {
  store: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
  user: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
  unpacked: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
  external: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
  policy: 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30',
  component: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
  orphan: 'bg-red-500/15 text-red-400 border border-red-500/30',
  unknown: 'bg-slate-500/15 text-slate-400 border border-slate-500/30',
  '': 'bg-surface-700 text-slate-500 border border-surface-600/40',
}
const LABELS: Record<string, MessageKey> = {
  store: 'Store', user: 'User-installed', unpacked: 'Unpacked', external: 'External installer', policy: 'Policy',
  component: 'Browser component', orphan: 'Orphan', unknown: 'Unknown source', '': 'Not reported',
}

interface Props {
  source: string
}

export default function InstallSourceBadge({ source }: Props) {
  const { tr } = useI18n()

  const normalized = source.toLowerCase()
  const recognized = Object.hasOwn(STYLES, normalized)
  return (
    <span className={clsx('inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium', recognized ? STYLES[normalized] : STYLES.unknown)}>
      {recognized ? tr(LABELS[normalized]) : source}
    </span>
  )
}
