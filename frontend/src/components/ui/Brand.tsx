import { useI18n } from '@/i18n'
export function BrandMark({ className = 'h-8 w-8' }: { className?: string }) {
  return <svg className={className} viewBox="0 0 40 40" fill="none" aria-hidden="true"><path d="M31 28a14 14 0 1 1 0-16" stroke="currentColor" strokeWidth="3.3" strokeLinecap="round"/><path d="M25 23a6 6 0 1 1 0-6" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" opacity=".45"/><circle cx="33" cy="20" r="3.6" fill="currentColor"/></svg>
}
export default function Brand() {
  const { tr } = useI18n()

  return <span className="inline-flex items-center gap-2.5 text-slate-100"><BrandMark className="h-9 w-9 text-accent shrink-0"/><span className="font-semibold leading-tight tracking-tight text-[15px]">Open Shadow <span className="text-accent">{tr("AI")}</span><span className="block text-[9px] uppercase tracking-[.22em] text-slate-400 font-normal mt-1">{tr("Evidence / Governance")}</span></span></span>
}
