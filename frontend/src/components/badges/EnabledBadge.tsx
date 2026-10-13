import { useI18n } from '@/i18n'
import type { MessageKey } from '@/i18n/messages'
import clsx from 'clsx'

// Keys are the `enabled` filter values of the inventory API; null means the agent reported no state.
const STYLES: Record<string, string> = {
  true: 'bg-emerald-500/15 text-emerald-400',
  false: 'bg-slate-500/15 text-slate-400 line-through',
  unknown: 'bg-surface-700 text-slate-500',
}
const LABELS: Record<string, MessageKey> = { true: 'Enabled', false: 'Disabled', unknown: 'Not reported' }

interface Props {
  enabled: boolean | null | string
}

export default function EnabledBadge({ enabled }: Props) {
  const { tr } = useI18n()

  const normalized = enabled == null ? 'unknown' : String(enabled).toLowerCase()
  const recognized = Object.hasOwn(STYLES, normalized)
  return (
    <span className={clsx('inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium', recognized ? STYLES[normalized] : STYLES.unknown)}>
      {normalized === 'true' && <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full" />}
      {recognized ? tr(LABELS[normalized]) : String(enabled)}
    </span>
  )
}
