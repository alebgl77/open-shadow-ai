import { AlertCircle, RotateCcw } from 'lucide-react'

interface Props {
  message?: string
  onRetry?: () => void
}

export default function ErrorAlert({ message = 'Failed to load data', onRetry }: Props) {
  return (
    <div className="flex flex-col items-center justify-center py-12 px-4">
      <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-3">
        <AlertCircle className="w-6 h-6 text-red-400" />
      </div>
      <p className="text-sm text-slate-400 mb-4">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-surface-700 text-slate-300 rounded-lg hover:bg-surface-600 transition-colors"
        >
          <RotateCcw className="w-4 h-4" />
          Retry
        </button>
      )}
    </div>
  )
}
