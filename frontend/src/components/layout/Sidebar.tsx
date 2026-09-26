import { NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Search, Users, Key, Puzzle, Cpu, Shield, BookOpen, Database, Settings, LogOut, X, ArrowUpRight } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import Brand from '@/components/ui/Brand'
import clsx from 'clsx'
const sections = [
  { label: 'Workspace', items: [[ '/dashboard', LayoutDashboard, 'Overview'], ['/discoveries', Search, 'Discoveries'], ['/users', Users, 'Identity signals']] },
  { label: 'Explore', items: [['/oauth-apps', Key, 'OAuth apps'], ['/extensions', Puzzle, 'Extensions'], ['/local-ai', Cpu, 'Local AI']] },
  { label: 'Governance', items: [['/governance', Shield, 'Policies'], ['/catalog', BookOpen, 'AI catalog'], ['/sources', Database, 'Sources']] },
  { label: 'Administration', admin: true, items: [['/settings', Settings, 'Settings']] },
]
export default function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user, mode, logout } = useAuthStore(); const navigate = useNavigate()
  return <>
    {open && <button className="fixed inset-0 bg-black/60 z-30 lg:hidden" onClick={onClose} aria-label="Close navigation overlay"/>}
    <aside id="app-navigation" className={clsx('fixed lg:static inset-y-0 left-0 z-40 flex flex-col w-[236px] bg-surface-900 border-r border-surface-600/35 shrink-0 transition-transform', open ? 'translate-x-0 visible' : '-translate-x-full invisible lg:visible lg:translate-x-0')}>
      <div className="h-20 px-5 flex items-center justify-between"><Brand/><button onClick={onClose} className="lg:hidden p-1" aria-label="Close navigation"><X size={18}/></button></div>
      <div className="mx-4 mb-7 px-3 py-3 border border-surface-600/40 rounded-lg flex items-center gap-3"><span className="w-7 h-7 rounded bg-accent/10 text-accent flex items-center justify-center text-xs font-mono">{mode === 'demo' ? 'D' : 'W'}</span><div><p className="text-xs font-medium">{mode === 'demo' ? 'Demo workspace' : 'Your workspace'}</p><p className="text-[10px] text-slate-500 mt-0.5">{mode === 'demo' ? 'Synthetic data only' : 'Self-hosted console'}</p></div></div>
      <nav aria-label="Main navigation" className="flex-1 overflow-y-auto px-3 space-y-6 pb-5">{sections.filter(section=>!section.admin || user?.role === 'admin').map(section=><div key={section.label}><p className="text-[9px] uppercase tracking-[.18em] text-slate-500 font-semibold px-3 mb-2">{section.label}</p><div className="space-y-1">{section.items.map(([path, icon, label])=>{ const Icon = icon as typeof Search; return <NavLink onClick={onClose} key={String(path)} to={String(path)} className={({isActive})=>clsx('nav-item flex items-center gap-3 px-3 py-2.5 rounded-lg text-[13px]', isActive ? 'active bg-accent/10 text-accent' : 'text-slate-400 hover:bg-surface-800 hover:text-slate-100')}><Icon size={17}/>{String(label)}</NavLink> })}</div></div>)}</nav>
      <div className="px-5 py-4 border-t border-surface-600/30"><a className="flex justify-between text-[11px] text-slate-500 hover:text-accent mb-5" href="https://github.com/alebgl77/open-shadow-ai" target="_blank" rel="noreferrer">Open source, by design<ArrowUpRight size={13}/></a><div className="flex items-center gap-3"><span className="w-8 h-8 rounded-full bg-surface-700 flex items-center justify-center text-xs font-medium text-slate-300">{user?.username.slice(0,2).toUpperCase()}</span><div className="min-w-0 flex-1"><p className="text-xs font-medium truncate">{user?.username}</p><p className="text-[10px] text-slate-500 capitalize mt-0.5">{user?.role}</p></div><button onClick={()=>{ logout(); navigate('/login') }} aria-label={mode === 'demo' ? 'Exit demo' : 'Sign out'} title={mode === 'demo' ? 'Exit demo' : 'Sign out'} className="p-2 text-slate-400 hover:text-accent"><LogOut size={16}/></button></div></div>
    </aside>
  </>
}
