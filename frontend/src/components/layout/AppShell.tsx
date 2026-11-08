import { useI18n } from '@/i18n'
import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import { useAuthStore } from '@/stores/auth'
import { FlaskConical } from 'lucide-react'

// Keep the dialog breakpoint aligned with Tailwind's lg layout.
const desktopQuery = '(min-width: 64rem)'
function subscribeToDesktop(callback: () => void) {
  const media = window.matchMedia?.(desktopQuery)
  media?.addEventListener('change', callback)
  return () => media?.removeEventListener('change', callback)
}
const isDesktop = () => window.matchMedia?.(desktopQuery).matches ?? true

export default function AppShell({ children }: { children: React.ReactNode }) {
  const { tr } = useI18n()
  const mode = useAuthStore(s => s.mode)
  const desktop = useSyncExternalStore(subscribeToDesktop, isDesktop)
  const [open, setOpen] = useState(false)
  const menuButton = useRef<HTMLButtonElement>(null)
  const content = useRef<HTMLElement>(null)
  const focusAfterClose = useRef<'menu' | 'content' | null>(null)
  const locationKey = useLocation().key
  const previousLocation = useRef(locationKey)

  const closeMenu = (target: 'menu' | 'content') => {
    if (!open) return
    focusAfterClose.current = target
    setOpen(false)
  }

  useEffect(() => {
    const moved = previousLocation.current !== locationKey
    previousLocation.current = locationKey
    if (open && (desktop || moved)) {
      focusAfterClose.current = 'content'
      setOpen(false)
      return
    }
    if (!open && focusAfterClose.current) {
      const target = focusAfterClose.current === 'menu' && !desktop ? menuButton : content
      focusAfterClose.current = null
      target.current?.focus()
    }
  }, [open, desktop, locationKey])

  return (
    <div className="flex h-dvh overflow-hidden bg-surface-950">
      <a href="#main-content" className="skip-link">{tr('Skip to content')}</a>
      <Sidebar desktop={desktop} open={open && !desktop} onClose={() => closeMenu('menu')} onNavigate={() => closeMenu('content')}/>
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar menuButton={menuButton} onMenu={() => setOpen(true)} menuOpen={open && !desktop}/>
        {mode === 'demo' && <div role="status" className="flex items-center gap-2 px-5 md:px-8 py-2 border-b border-amber-500/15 bg-amber-500/[.06] text-amber-200/90 text-[11px]"><FlaskConical size={13} className="shrink-0"/><span><strong className="font-semibold">{tr("Demo workspace")}</strong>{' '}<span className="hidden sm:inline">{tr("· Synthetic evidence for exploration.")}{' '}</span>{tr("Changes stay in this session.")}</span></div>}
        <main ref={content} tabIndex={-1} id="main-content" className="relative flex-1 overflow-auto px-5 py-7 md:p-8">
          <div className="max-w-[1600px] mx-auto">{children}</div>
        </main>
      </div>
    </div>
  )
}
