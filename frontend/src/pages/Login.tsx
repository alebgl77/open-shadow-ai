import { LanguageSelector, useI18n } from '@/i18n'
import { useState } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, ScanLine, Layers3, ShieldCheck, ArrowUpRight } from 'lucide-react'
import axios from 'axios'
import { login as apiLogin, getAuthProviders, SSO_FAILURE_MESSAGE } from '@/api/auth'
import SsoOptions from '@/components/auth/SsoOptions'
import { useAuthStore } from '@/stores/auth'
import Brand, { BrandMark } from '@/components/ui/Brand'

export default function Login() {
  const { tr, textLabel } = useI18n()

  const [username, setUsername] = useState(''); const [password, setPassword] = useState('')
  const [error, setError] = useState(''); const [loading, setLoading] = useState(false)
  const auth = useAuthStore(); const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const providers = useQuery({ queryKey: ['auth-providers'], queryFn: getAuthProviders, enabled: !auth.isAuthenticated, retry: false, staleTime: 60_000 })
  const localEnabled = providers.isError || providers.data?.local_enabled !== false
  if (auth.isAuthenticated) return <Navigate to="/dashboard" replace />
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(''); setLoading(true)
    try { const res = await apiLogin(username, password); auth.login(res.csrf_token, res.user); navigate('/dashboard') }
    catch (error) { setError(axios.isAxiosError(error) && error.response?.status === 401 ? 'The username or password is incorrect.' : 'Unable to reach your workspace. Check the service connection and try again.') }
    finally { setLoading(false) }
  }
  async function demo() { const { resetDemo } = await import('@/api/demo'); resetDemo(); auth.enterDemo(); navigate('/dashboard') }
  return <div className="login-scene min-h-screen flex flex-col">
    <header className="flex items-center justify-between px-6 md:px-12 py-7"><Brand/><div className="flex items-center gap-4"><LanguageSelector/><a href="https://github.com/alebgl77/open-shadow-ai" target="_blank" rel="noreferrer" className="text-xs text-slate-400 flex items-center gap-2 hover:text-accent">{tr("View on GitHub")} <ArrowUpRight size={14}/></a></div></header>
    <main className="login-grid w-full max-w-[1260px] mx-auto grid lg:grid-cols-[1.25fr_1fr] gap-12 lg:gap-24 px-6 md:px-12 py-12 md:py-20 flex-1 items-center">
      <section><p className="eyebrow mb-6">{tr("Open source · Evidence first")}</p><h1 className="text-5xl md:text-[68px] leading-[1.06] tracking-[-.055em] font-semibold max-w-[650px]">{tr("See the evidence.")}<br/><span className="text-accent">{tr("Govern the AI.")}</span></h1><p className="text-slate-400 leading-relaxed text-lg max-w-[470px] mt-7">{tr("Bring AI signals into focus. Discover tools, understand the evidence, and make informed governance decisions.")}</p>
      <div className="mt-12 space-y-6">{[[ScanLine, tr("Discover what your sources can see"), tr("Network, endpoint, browser and identity signals.")], [Layers3, tr("Understand the evidence"), tr("Trace findings to observed activity and source coverage.")], [ShieldCheck, tr("Review with context"), tr("Classify tools and record your decisions.")]].map(([Icon, title, description]) => { const ItemIcon = Icon as typeof ScanLine; return <div className="flex gap-4" key={String(title)}><div className="w-10 h-10 flex items-center justify-center border border-surface-600/50 rounded-xl text-accent"><ItemIcon size={19}/></div><div><h2 className="text-sm font-medium">{String(title)}</h2><p className="text-sm text-slate-400 mt-1">{String(description)}</p></div></div> })}</div></section>
      <section className="login-panel p-7 md:p-9 rounded-2xl border border-surface-600/50 bg-surface-900 shadow-2xl shadow-black/20"><BrandMark className="w-10 h-10 text-accent mb-6"/><p className="eyebrow mb-2">{tr("Your workspace")}</p><h2 className="text-2xl font-semibold tracking-tight">{tr("Welcome back")}</h2><p className="text-sm text-slate-400 mt-2 mb-7">{tr("Sign in to your self-hosted console.")}</p>{searchParams.has('sso_error') && <p role="alert" className="mb-5 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs leading-relaxed text-slate-300">{textLabel(SSO_FAILURE_MESSAGE)}</p>}<SsoOptions data={providers.data} pending={providers.isPending} failed={providers.isError} disabled={loading} retry={() => { void providers.refetch() }}/>{localEnabled ? <form onSubmit={submit} className="space-y-5"><div><label htmlFor="username" className="field-label">{tr("Username")}</label><input id="username" autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} placeholder={tr("Your username")} required className="field w-full"/></div><div><label htmlFor="password" className="field-label">{tr("Password")}</label><input id="password" type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} placeholder={tr("Your password")} required className="field w-full"/></div>{error && <p role="alert" className="text-red-300 bg-red-500/10 p-3 rounded-lg text-sm">{textLabel(error)}</p>}<button disabled={loading} className="primary-button w-full justify-center">{loading ? tr("Signing in…") : tr("Sign in to workspace")}<ArrowRight size={16}/></button></form> : <p className="text-xs text-slate-400">{tr("Local account sign-in is disabled for this workspace.")}</p>}
      <div className="mt-7 border-t border-surface-600/40 pt-6"><p className="text-sm font-medium">{tr("Take a look around")}</p><p className="text-xs leading-relaxed text-slate-400 mt-1 mb-4">{tr("Explore synthetic evidence. No account or connected sources needed; changes stay in this session.")}</p><button onClick={demo} disabled={loading} className="secondary-button w-full justify-center">{tr("Explore the demo")}<ArrowUpRight size={15}/></button></div><p className="text-[11px] text-slate-500 leading-relaxed mt-6">{tr("Your workspace session can be restored after a reload. Demo changes stay in this session.")}</p></section>
    </main><footer className="px-6 md:px-12 pb-6 text-xs text-slate-500">{tr("For IT governance and security review. Not for employee performance monitoring.")}</footer>
  </div>
}
