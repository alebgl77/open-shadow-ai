import { useState, useEffect } from 'react'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import { useAuthStore } from '@/stores/auth'
import { FlaskConical } from 'lucide-react'
export default function AppShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false); const mode = useAuthStore(s=>s.mode)
  useEffect(()=>{ const close = (event: KeyboardEvent) => { if (event.key === 'Escape') setOpen(false) }; window.addEventListener('keydown',close); return ()=>window.removeEventListener('keydown',close) },[])
  return <div className="flex h-dvh overflow-hidden bg-surface-950"><a href="#main-content" className="skip-link">Skip to content</a><Sidebar open={open} onClose={()=>setOpen(false)}/><div className="flex flex-col flex-1 min-w-0 overflow-hidden"><TopBar onMenu={()=>setOpen(!open)} menuOpen={open}/>{mode === 'demo' && <div role="status" className="flex items-center gap-2 px-5 md:px-8 py-2 border-b border-amber-500/15 bg-amber-500/[.06] text-amber-200/90 text-[11px]"><FlaskConical size={13} className="shrink-0"/><span><strong className="font-semibold">Demo workspace</strong><span className="hidden sm:inline"> · Synthetic evidence for exploration.</span> Changes stay in this session.</span></div>}<main id="main-content" className="flex-1 overflow-auto px-5 py-7 md:p-8"><div className="max-w-[1600px] mx-auto">{children}</div></main></div></div>
}
