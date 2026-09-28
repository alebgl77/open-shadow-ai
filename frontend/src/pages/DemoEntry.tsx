import { useEffect, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { logout as revokeSession } from '@/api/auth'
export default function DemoEntry() {
  // A signed-in workspace is never replaced by the synthetic demo without an explicit sign-out.
  const liveSession = useAuthStore(s => s.mode === 'live' && s.isAuthenticated)
  const [ready, setReady] = useState(false)
  useEffect(()=>{
    if (liveSession) return
    let active = true
    import('@/api/demo').then(({resetDemo})=>{ if (active) { resetDemo(); useAuthStore.getState().enterDemo(); setReady(true) } })
    return ()=>{ active = false }
  },[liveSession])
  const signOutForDemo = () => {
    const { token, logout } = useAuthStore.getState()
    if (token) void revokeSession(token).catch(()=>undefined)
    logout()
  }
  if (liveSession) return <div className="p-8 space-y-4 max-w-lg"><p className="eyebrow">Synthetic demo</p><p className="page-description">You are signed in to your workspace. Opening the demo ends this session.</p><div className="flex gap-2"><Link to="/dashboard" className="secondary-button">Back to workspace</Link><button type="button" onClick={signOutForDemo} className="primary-button">Sign out and open the demo</button></div></div>
  return ready ? <Navigate to="/dashboard" replace/> : <p className="p-8 text-slate-400" role="status">Opening the synthetic demo workspace…</p>
}
