import { useEffect, useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { ArrowLeft, LoaderCircle } from 'lucide-react'
import { exchangeSsoSession, SSO_FAILURE_MESSAGE } from '@/api/auth'
import { useAuthStore } from '@/stores/auth'
import Brand from '@/components/ui/Brand'

export default function SsoCallback() {
  const [failed, setFailed] = useState(false)
  const authenticated = useAuthStore(state => state.isAuthenticated)
  const login = useAuthStore(state => state.login)
  const navigate = useNavigate()
  useEffect(() => {
    if (authenticated) return
    let active = true
    const startedSession = useAuthStore.getState().session
    // No query string, fragment, provider token, or redirect target is consumed.
    // The backend validates a one-use HttpOnly ticket before returning a session.
    exchangeSsoSession().then(session => {
      if (!active) return
      if (useAuthStore.getState().session !== startedSession) { setFailed(true); return }
      login(session.access_token, session.user)
      navigate('/dashboard', { replace: true })
    }).catch(() => { if (active) setFailed(true) })
    return () => { active = false }
  }, [authenticated, login, navigate])
  if (authenticated) return <Navigate to="/dashboard" replace />
  return <main className="login-scene min-h-screen flex flex-col items-center justify-center p-6"><Brand/><section className="login-panel mt-8 w-full max-w-md rounded-2xl border border-surface-600/50 bg-surface-900 p-8"><p className="eyebrow mb-3">Workspace sign-in</p><h1 className="text-2xl font-semibold tracking-tight">{failed ? 'Sign-in did not complete' : 'Completing single sign-on'}</h1>{failed ? <><p role="alert" className="mt-4 text-sm leading-relaxed text-slate-300">{SSO_FAILURE_MESSAGE}</p><Link to="/login" replace className="secondary-button mt-6"><ArrowLeft size={14}/>Back to sign in</Link></> : <p role="status" className="flex items-center gap-3 mt-5 text-sm text-slate-400"><LoaderCircle size={17} className="animate-spin"/>Verifying your workspace session…</p>}</section></main>
}
