import { useI18n } from '@/i18n'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import client from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import type { User } from '@/stores/auth'
import type { AuditEntry } from '@/types'
import ErrorAlert from '@/components/ui/ErrorAlert'
import { TableSkeleton } from '@/components/ui/LoadingSkeleton'
export default function Settings() {
  const { tr, textLabel, enumLabel, formatDate } = useI18n()

  const [tab,setTab] = useState<'users'|'audit'>('users')
  const role = useAuthStore(s=>s.user?.role)
  const users = useQuery({queryKey:['users'], queryFn:()=>client.get<Array<User & {last_login_at?:string}>>('/settings/users').then(r=>r.data), enabled:tab==='users' && role==='admin'})
  const audit = useQuery({queryKey:['audit-logs'], queryFn:()=>client.get<AuditEntry[]>('/audit/logs?page_size=50').then(r=>r.data), enabled:tab==='audit' && role==='admin'})
  if (role!=='admin') return <ErrorAlert message={tr("Workspace administration requires an administrator role.")}/>
  const active = tab==='users' ? users : audit
  return <div className="space-y-5"><div><p className="eyebrow mb-2">{tr("Workspace administration")}</p><h1 className="page-heading">{tr("Settings")}</h1><p className="page-description">{tr("Review console access and recorded governance actions.")}</p></div><div className="stat-card text-xs text-slate-400 leading-relaxed">{tr("Open Shadow AI supports IT governance and security review. Do not use identity signals for employee performance evaluation or behavioral profiling. Accounts are managed through the administration API.")}</div><div className="flex gap-2" role="tablist" aria-label={tr("Settings sections")}>{(['users','audit'] as const).map(t=><button role="tab" aria-selected={tab===t} className={tab===t?'primary-button':'secondary-button'} key={t} onClick={()=>setTab(t)}>{t==='users'?tr("Console users"):tr("Audit log")}</button>)}</div>{active.isError ? <ErrorAlert onRetry={active.refetch}/> : active.isPending ? <TableSkeleton rows={5} columns={4}/> : <div className="stat-card p-0! overflow-x-auto">{tab==='users' ? <table className="w-full text-sm"><thead className="text-left text-xs text-slate-500"><tr>{[tr("Username"),tr("Email"),tr("Role"),tr("Status"),tr("Last login")].map(h=><th className="p-4" key={h}>{textLabel(h)}</th>)}</tr></thead><tbody>{users.data?.map(u=><tr key={u.user_id} className="data-row"><td className="p-4 font-medium">{u.username}</td><td className="p-4 text-slate-400">{u.email||'—'}</td><td className="p-4"><span className="badge bg-accent/10 text-accent">{enumLabel(u.role)}</span></td><td className="p-4 text-slate-400">{u.is_active?tr("Active"):tr("Inactive")}</td><td className="p-4 text-xs text-slate-400">{u.last_login_at ? formatDate(u.last_login_at) : tr("Not recorded")}</td></tr>)}</tbody></table> : !audit.data?.length ? <p className="p-6 text-sm text-slate-400">{tr("No audit actions recorded yet. Review a detection to record a decision.")}</p> : <table className="w-full text-sm"><thead className="text-left text-xs text-slate-500"><tr>{[tr("Time"),tr("User"),tr("Action"),tr("Resource")].map(h=><th className="p-4" key={h}>{textLabel(h)}</th>)}</tr></thead><tbody>{audit.data.map(log=><tr key={log.audit_id} className="data-row"><td className="p-4 text-xs text-slate-400">{formatDate(log.timestamp)}</td><td className="p-4">{log.username}</td><td className="p-4 text-xs">{log.action}</td><td className="p-4 text-xs font-mono text-slate-400">{log.resource_type ? `${log.resource_type}/${log.resource_id?.slice(0,8)}` : '—'}</td></tr>)}</tbody></table>}</div>}{tab==='audit' && <p className="text-xs text-slate-500">{tr("Latest 50 recorded actions.")}</p>}</div>
}
