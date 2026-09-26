import { ArrowRight, Building2, RefreshCw } from 'lucide-react'
import { SSO_LOGIN_PATH, type AuthProviders } from '@/api/auth'

interface Props {
  data?: AuthProviders
  pending: boolean
  failed: boolean
  disabled?: boolean
  retry: () => void
}
export default function SsoOptions({ data, pending, failed, disabled, retry }: Props) {
  if (pending) return <p role="status" className="text-xs text-slate-500 mb-5">Checking sign-in options…</p>
  if (failed) return <div className="mb-5 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-3"><p role="alert" className="text-xs leading-relaxed text-slate-300">Single sign-on availability could not be checked. Local account sign-in is still available.</p><button type="button" disabled={disabled} onClick={retry} className="mt-2 inline-flex items-center gap-1.5 text-xs text-accent"><RefreshCw size={12}/>Check again</button></div>
  if (!data?.sso?.enabled) return null
  return <div className="mb-6"><button type="button" disabled={disabled} onClick={() => window.location.assign(SSO_LOGIN_PATH)} className="secondary-button w-full justify-center"><Building2 size={16} className="shrink-0"/><span className="break-words min-w-0">Continue with {data.sso.label}</span><ArrowRight size={15} className="shrink-0"/></button>{data.local_enabled && <div className="flex items-center gap-3 text-[10px] text-slate-500 mt-6"><span className="h-px bg-surface-600/40 flex-1"/>or use a local account<span className="h-px bg-surface-600/40 flex-1"/></div>}</div>
}
