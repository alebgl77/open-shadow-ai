import { LanguageSelector, useI18n } from '@/i18n'
import { useQuery } from '@tanstack/react-query'
import { Menu, CircleHelp, Activity } from 'lucide-react'
import { SOURCE_HEALTH_REFRESH_MS, sourceHealthQueryOptions } from '@/api/dashboard'
import { Link, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import type { Ref } from 'react'

export default function TopBar({ onMenu, menuOpen, menuButton }: {
  onMenu: () => void
  menuOpen: boolean
  menuButton: Ref<HTMLButtonElement>
}) {
  const { tr, formatNumber } = useI18n()
  const mode = useAuthStore(s => s.mode)
  const session = useAuthStore(s => s.session)
  // The shell owns polling; pages observe this same session-scoped snapshot.
  const query = useQuery({ ...sourceHealthQueryOptions(mode, session), refetchInterval: SOURCE_HEALTH_REFRESH_MS })
  const recentSources = query.isSuccess ? query.data.filter(source => source.status === 'active').length : null
  const count = recentSources === null ? null : formatNumber(recentSources)
  const status = query.isError ? tr('Source status unavailable') : count === null ? tr('Checking sources…') : tr('Recent sources: {count}', { count })
  const sourceLabel = count === null ? status : status + '. ' + tr('Events in the hour before the last check.')
  const page = useLocation().pathname.split('/')[1]
  const pages: Record<string, string> = {
    dashboard: tr('Overview'), discoveries: tr('Discoveries'), network: tr('Network'),
    cartography: tr('AI cartography'), 'oauth-apps': tr('OAuth apps'), extensions: tr('Extensions'),
    'local-ai': tr('Local AI'), governance: tr('Policies'), catalog: tr('AI catalog'),
    sources: tr('Sources'), settings: tr('Settings'),
  }

  return (
    <header className="min-h-16 shrink-0 border-b border-surface-600/30 flex items-center justify-between gap-2 px-3 sm:px-5 md:px-8 bg-surface-950">
      <div className="flex min-w-0 items-center gap-2 sm:gap-3">
        <button type="button" ref={menuButton} onClick={onMenu} aria-expanded={menuOpen} aria-controls="app-navigation"
          aria-label={tr('Open navigation')} className="lg:hidden flex size-8 shrink-0 items-center justify-center text-slate-300">
          <Menu size={20} aria-hidden="true"/>
        </button>
        <span className="text-xs text-slate-500 hidden sm:inline">{tr('Workspace')}</span>
        <span className="text-slate-600 hidden sm:inline">/</span>
        <span className="break-words min-w-0 text-xs text-slate-300">{pages[page] || tr('Workspace')}</span>
      </div>
      <div className="flex shrink-0 items-center gap-1.5 sm:gap-3 [&_select]:px-2 sm:[&_select]:px-3">
        <LanguageSelector/>
        <Link to="/sources" aria-label={sourceLabel} title={sourceLabel}
          className="flex min-h-8 items-center gap-1.5 px-1 text-[11px] text-slate-400 hover:text-accent">
          <Activity size={13} aria-hidden="true" className={recentSources ? 'text-accent' : 'text-slate-500'}/>
          <span aria-hidden="true" className="md:hidden tabular-nums">{count ?? '—'}</span>
          <span aria-hidden="true" className="hidden md:inline">{status}</span>
        </Link>
        <a href="https://github.com/alebgl77/open-shadow-ai#readme" target="_blank" rel="noreferrer" aria-label={tr('Documentation')}
          title={tr('Documentation')} className="flex size-8 items-center justify-center text-slate-500 hover:text-accent">
          <CircleHelp size={16} aria-hidden="true"/>
        </a>
      </div>
    </header>
  )
}
