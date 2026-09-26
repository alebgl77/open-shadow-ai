export default function ApprovalBadge({ status }: { status?: 'none' | 'active' | 'expired' }) {
  if (status !== 'expired') return null
  return <span className="badge bg-amber-500/15 text-amber-300 border border-amber-500/30">Approval expired</span>
}
