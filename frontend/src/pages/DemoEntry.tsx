import { LanguageSelector, useI18n } from '@/i18n'
import { useEffect, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { logout as revokeSession } from '@/api/auth'
export default function DemoEntry() {
  const { tr } = useI18n()

  // A signed-in workspace is never replaced by the synthetic demo without an explicit sign-out.
  const liveSession = useAuthStore(s => s.mode === 'live' && s.isAuthenticated)
  const restoring = useAuthStore(s => s.restoring)
  const [ready, setReady] = useState(false)
  useEffect(()=>{
    if (liveSession || restoring) return
    let active = true
    import('@/api/demo').then(({resetDemo})=>{ if (active) { resetDemo(); useAuthStore.getState().enterDemo(); setReady(true) } })
    return ()=>{ active = false }
  },[liveSession, restoring])
  const [signOut, setSignOut] = useState<'idle' | 'pending' | 'failed'>('idle')
  const signOutForDemo = async () => {
    const { csrfToken, session } = useAuthStore.getState()
    // Revoke before switching: demo requests never reach the server, and a cookie left valid
    // would bring the workspace back on the next reload.
    if (csrfToken) {
      setSignOut('pending')
      try { await revokeSession(csrfToken) } catch { setSignOut('failed'); return }
    }
    if (useAuthStore.getState().session === session) useAuthStore.getState().logout()
  }
  if (restoring) return <p className="p-8 text-slate-400" role="status">{tr("Checking your session…")}</p>
  if (liveSession) return <div className="p-8 space-y-4 max-w-lg"><LanguageSelector/><p className="eyebrow">{tr("Synthetic demo")}</p><p className="page-description">{tr("You are signed in to your workspace. Opening the demo ends this session.")}</p><div className="flex gap-2"><Link to="/dashboard" className="secondary-button">{tr("Back to workspace")}</Link><button type="button" onClick={()=>void signOutForDemo()} disabled={signOut === 'pending'} className="primary-button">{tr("Sign out and open the demo")}</button></div>{signOut === 'failed' && <p role="alert" className="text-xs text-red-300">{tr("Sign-out did not reach the server, so your workspace session is still active. Try again.")}</p>}</div>
  return ready ? <Navigate to="/dashboard" replace/> : <p className="p-8 text-slate-400" role="status">{tr("Opening the synthetic demo workspace…")}</p>
}
