import { useQuery } from '@tanstack/react-query'
import { Menu, CircleHelp, Activity } from 'lucide-react'
import { getSourceHealth } from '@/api/dashboard'
import { Link, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
export default function TopBar({ onMenu, menuOpen }: { onMenu: () => void; menuOpen: boolean }) {
  const query = useQuery({ queryKey: ['source-health'], queryFn: getSourceHealth, refetchInterval: 60_000 })
  const count = query.data?.filter(s=>s.status === 'active').length
  const mode = useAuthStore(s=>s.mode); const location = useLocation()
  const page = location.pathname.split('/')[1].replaceAll('-', ' ')
  return <header className="h-[64px] shrink-0 border-b border-surface-600/30 flex items-center justify-between gap-3 px-5 md:px-8 bg-surface-950"><div className="flex items-center gap-3"><button onClick={onMenu} aria-expanded={menuOpen} aria-controls="app-navigation" aria-label="Open navigation" className="lg:hidden p-1 text-slate-300"><Menu size={20}/></button><span className="text-xs text-slate-500 hidden sm:inline">Workspace</span><span className="text-slate-600 hidden sm:inline">/</span><span className="capitalize text-xs text-slate-300">{page === 'dashboard' ? 'Overview' : page}</span></div><div className="flex items-center gap-5"><Link to="/sources" className="flex items-center gap-2 text-[11px] text-slate-400"><Activity size={13} className={count ? 'text-accent' : 'text-slate-500'}/>{query.isError ? 'Source status unavailable' : query.isPending ? 'Checking sources…' : `${count} ${mode === 'demo' ? 'demo ' : ''}sources active`}</Link><a href="https://github.com/alebgl77/open-shadow-ai#readme" target="_blank" rel="noreferrer" aria-label="Documentation" title="Documentation" className="text-slate-500 hover:text-accent"><CircleHelp size={16}/></a></div></header>
}
