/**
 * Tiny inline source type indicators used in tables.
 */

const SOURCE_COLORS: Record<string, string> = {
  dns: 'bg-blue-500',
  proxy: 'bg-purple-500',
  endpoint: 'bg-emerald-500',
  browser: 'bg-amber-500',
  oauth: 'bg-red-500',
  casb: 'bg-cyan-500',
  network: 'bg-cyan-400',
}

export const sourceLabel = (source: string) => source === 'network' ? 'Passive network' : source

interface Props {
  sources: string[]
}

export default function SourceIcons({ sources }: Props) {
  return (
    <div className="flex gap-1">
      {sources.map((s) => (
        <span
          key={s}
          title={sourceLabel(s)}
          className="text-[10px] bg-surface-700 px-1.5 py-0.5 rounded font-mono text-slate-400 flex items-center gap-1"
        >
          <span className={`w-1.5 h-1.5 rounded-full ${SOURCE_COLORS[s] || 'bg-slate-500'}`} />
          {sourceLabel(s)}
        </span>
      ))}
    </div>
  )
}
