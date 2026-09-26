import clsx from 'clsx'

interface Props {
  rows?: number
  columns?: number
  type?: 'table' | 'cards' | 'detail'
}

function SkeletonPulse({ className }: { className?: string }) {
  return <div className={clsx('animate-pulse bg-surface-700/50 rounded', className)} />
}

export function TableSkeleton({ rows = 8, columns = 6 }: { rows?: number; columns?: number }) {
  return (
    <div className="bg-surface-800 border border-surface-600/30 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex gap-4 px-4 py-3 border-b border-surface-600/30">
        {Array.from({ length: columns }).map((_, i) => (
          <SkeletonPulse key={i} className="h-3 flex-1" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4 px-4 py-4 border-b border-surface-700/30">
          {Array.from({ length: columns }).map((_, j) => (
            <SkeletonPulse key={j} className={clsx('h-3', j === 0 ? 'w-40' : 'flex-1')} />
          ))}
        </div>
      ))}
    </div>
  )
}

export function CardsSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="stat-card space-y-3">
          <SkeletonPulse className="h-4 w-16" />
          <SkeletonPulse className="h-8 w-24" />
          <SkeletonPulse className="h-3 w-32" />
        </div>
      ))}
    </div>
  )
}

export function DetailSkeleton() {
  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <SkeletonPulse className="h-7 w-64" />
        <div className="flex gap-2">
          <SkeletonPulse className="h-5 w-16 rounded-full" />
          <SkeletonPulse className="h-5 w-20 rounded-full" />
          <SkeletonPulse className="h-5 w-16 rounded-full" />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2 space-y-4">
          <div className="stat-card space-y-3">
            <SkeletonPulse className="h-4 w-32" />
            <SkeletonPulse className="h-24 w-full" />
          </div>
          <div className="stat-card space-y-3">
            <SkeletonPulse className="h-4 w-40" />
            <SkeletonPulse className="h-16 w-full" />
          </div>
        </div>
        <div className="stat-card space-y-3">
          <SkeletonPulse className="h-4 w-28" />
          <SkeletonPulse className="h-8 w-full" />
          <SkeletonPulse className="h-8 w-full" />
          <SkeletonPulse className="h-20 w-full" />
        </div>
      </div>
    </div>
  )
}

export default function LoadingSkeleton({ type = 'table', rows, columns }: Props) {
  if (type === 'cards') return <CardsSkeleton count={rows} />
  if (type === 'detail') return <DetailSkeleton />
  return <TableSkeleton rows={rows} columns={columns} />
}
