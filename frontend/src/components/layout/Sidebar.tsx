import { useI18n } from '@/i18n'
import { useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Search, Key, Puzzle, Cpu, Shield, BookOpen, Database, Settings, LogOut, X, ArrowUpRight, Network, Box } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import { logout as revokeSession } from '@/api/auth'
import Brand from '@/components/ui/Brand'
import clsx from 'clsx'
const sections = [
  { label: 'Workspace', items: [[ '/dashboard', LayoutDashboard, 'Overview'], ['/discoveries', Search, 'Discoveries']] },
  { label: 'Explore', items: [['/cartography', Box, 'AI cartography'], ['/network', Network, 'Network'], ['/oauth-apps', Key, 'OAuth apps'], ['/extensions', Puzzle, 'Extensions'], ['/local-ai', Cpu, 'Local AI']] },
  { label: 'Governance', items: [['/governance', Shield, 'Policies'], ['/catalog', BookOpen, 'AI catalog'], ['/sources', Database, 'Sources']] },
  { label: 'Administration', admin: true, items: [['/settings', Settings, 'Settings']] },
]
export default function Sidebar({ desktop = true, open, onClose, onNavigate = onClose }: {
  desktop?: boolean
  open: boolean
  onClose: () => void
  onNavigate?: () => void
}) {
  const { tr, textLabel, enumLabel } = useI18n()

  const { user, mode, logout } = useAuthStore(); const navigate = useNavigate()
  const [signOut, setSignOut] = useState<'idle' | 'pending' | 'failed'>('idle')
  const canInvestigate = user?.role === 'admin' || user?.role === 'analyst'
  const dialog = useRef<HTMLDialogElement>(null)
  const closeButton = useRef<HTMLButtonElement>(null)

  useLayoutEffect(() => {
    const panel = dialog.current
    if (!open || desktop || !panel) return
    panel.showModal()
    closeButton.current?.focus()
    return () => { if (panel.open) panel.close() }
  }, [desktop, open])

  const wrapFocus = (event: KeyboardEvent<HTMLDialogElement>) => {
    if (event.key !== 'Tab') return
    const controls = event.currentTarget.querySelectorAll<HTMLElement>('a[href], button:not(:disabled)')
    const first = controls[0]
    const last = controls[controls.length - 1]
    const boundary = event.shiftKey ? first : last
    if (boundary && document.activeElement === boundary) {
      event.preventDefault()
      const destination = event.shiftKey ? last : first
      destination.focus()
    }
  }

  const leave = async () => {
    const { csrfToken, session } = useAuthStore.getState()
    if (mode === 'live' && csrfToken) {
      // The server deletes the HttpOnly cookie; leaving earlier would let a reload restore the session.
      setSignOut('pending')
      try { await revokeSession(csrfToken) } catch { setSignOut('failed'); return }
      // A 401 has already signed this tab out.
      if (useAuthStore.getState().session !== session) return
    }
    logout(); navigate('/login')
  }
  const panel = <>
      <div className="h-20 shrink-0 px-5 flex items-center justify-between"><Brand/>{!desktop &&
        <button type="button" ref={closeButton} onClick={onClose} className="flex size-8 shrink-0 items-center justify-center" aria-label={tr('Close navigation')}>
          <X size={18} aria-hidden="true"/>
        </button>}
      </div>
      <div className="mx-4 mb-7 px-3 py-3 border border-surface-600/40 rounded-lg flex items-center gap-3"><span className="w-7 h-7 rounded-sm bg-accent/10 text-accent flex items-center justify-center text-xs font-mono">{mode === 'demo' ? 'D' : 'W'}</span><div><p className="text-xs font-medium">{mode === 'demo' ? tr("Demo workspace") : tr("Your workspace")}</p><p className="text-[10px] text-slate-500 mt-0.5">{mode === 'demo' ? tr("Synthetic data only") : tr("Self-hosted console")}</p></div></div>
      <nav aria-label={tr("Main navigation")} className="flex-1 overflow-y-auto px-3 space-y-6 pb-5">{sections.filter(section=>!section.admin || user?.role === 'admin').map(section=><div key={textLabel(section.label)}><p className="text-[9px] uppercase tracking-[.18em] text-slate-500 font-semibold px-3 mb-2">{textLabel(section.label)}</p><div className="space-y-1">{section.items.filter(([path]) => canInvestigate || (path !== '/cartography' && path !== '/network')).map(([path, icon, label])=>{ const Icon = icon as typeof Search; return <NavLink onClick={event => { if (event.button === 0 && !event.ctrlKey && !event.metaKey && !event.altKey && !event.shiftKey) onNavigate() }} key={String(path)} to={String(path)} className={({isActive})=>clsx('nav-item flex items-center gap-3 px-3 py-2.5 rounded-lg text-[13px]', isActive ? 'active bg-accent/10 text-accent' : 'text-slate-400 hover:bg-surface-800 hover:text-slate-100')}><Icon size={17}/>{textLabel(String(label))}</NavLink> })}</div></div>)}</nav>
      <div className="px-5 py-4 border-t border-surface-600/30"><a className="flex justify-between text-[11px] text-slate-500 hover:text-accent mb-5" href="https://github.com/alebgl77/open-shadow-ai" target="_blank" rel="noreferrer">{tr("Open source, by design")}<ArrowUpRight size={13}/></a><div className="flex items-center gap-3"><span className="w-8 h-8 rounded-full bg-surface-700 flex items-center justify-center text-xs font-medium text-slate-300">{user?.username.slice(0,2).toUpperCase()}</span><div className="min-w-0 flex-1"><p className="text-xs font-medium truncate">{user?.username}</p><p className="text-[10px] text-slate-500 capitalize mt-0.5">{user?.role && enumLabel(user.role)}</p></div><button onClick={()=>void leave()} disabled={signOut === 'pending'} aria-label={mode === 'demo' ? tr("Exit demo") : tr("Sign out")} title={mode === 'demo' ? tr("Exit demo") : tr("Sign out")} className="p-2 text-slate-400 hover:text-accent disabled:opacity-50"><LogOut size={16}/></button></div>{signOut === 'failed' && <p role="alert" className="text-xs text-red-300 mt-2">{tr("Sign-out did not reach the server, so this session is still active. Try again.")}</p>}</div>
  </>

  if (desktop) {
    return <aside id="app-navigation" className="flex flex-col w-[236px] bg-surface-900 border-r border-surface-600/35 shrink-0">{panel}</aside>
  }
  return (
    <dialog
      ref={dialog}
      id="app-navigation"
      aria-label={tr('Main navigation')}
      onCancel={event => { event.preventDefault(); onClose() }}
      onClick={event => { if (event.target === event.currentTarget) onClose() }}
      onKeyDown={wrapFocus}
      className="fixed inset-y-0 left-0 right-auto h-dvh max-h-none m-0 p-0 w-[236px] max-w-full bg-surface-900 text-slate-100 border-r border-surface-600/35 backdrop:bg-black/60"
    >
      <div className="flex h-full flex-col">{panel}</div>
    </dialog>
  )
}
