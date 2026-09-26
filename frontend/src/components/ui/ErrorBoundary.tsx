import React from 'react'
import { AlertTriangle, RotateCcw } from 'lucide-react'

interface Props {
  children: React.ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export default class ErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] p-8">
          <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-4">
            <AlertTriangle className="w-7 h-7 text-red-400" />
          </div>
          <h3 className="text-lg font-medium text-slate-200 mb-2">Something went wrong</h3>
          <p className="text-sm text-slate-500 mb-1 text-center max-w-md">
            An unexpected error occurred. Try refreshing the page.
          </p>
          {this.state.error && (
            <pre className="text-xs text-red-400/60 font-mono mt-2 max-w-lg truncate">
              {this.state.error.message}
            </pre>
          )}
          <button
            onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload() }}
            className="mt-6 flex items-center gap-2 px-4 py-2 text-sm bg-surface-700 text-slate-300 rounded-lg hover:bg-surface-600 transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
            Reload page
          </button>
        </div>
      )
    }

    return this.props.children
  }
}
