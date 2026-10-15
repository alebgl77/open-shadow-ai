import { useEffect, useRef } from 'react'
import { useI18n } from '@/i18n'
import type { Graph, Selection } from './model'
import type { SceneHandle } from './engine'

export default function CartographyScene({ graph, selection, onSelect, onUnavailable, labels }: { graph: Graph; selection: Selection; onSelect: (selection: Selection) => void; onUnavailable: () => void; labels: Map<string, string> }) {
  const { tr } = useI18n()
  const container = useRef<HTMLDivElement>(null), handle = useRef<SceneHandle>()
  const callbacks = useRef({ onSelect, onUnavailable }); callbacks.current = { onSelect, onUnavailable }
  const currentSelection = useRef(selection); currentSelection.current = selection
  useEffect(() => {
    let cancelled = false
    void import('./engine').then(({ createScene }) => {
      if (cancelled || !container.current?.isConnected) return
      try {
        handle.current = createScene(container.current, graph, labels, value => callbacks.current.onSelect(value), () => callbacks.current.onUnavailable())
        handle.current.updateSelection(currentSelection.current)
      } catch { if (!cancelled) callbacks.current.onUnavailable() }
    }).catch(() => { if (!cancelled) callbacks.current.onUnavailable() })
    return () => { cancelled = true; handle.current?.dispose(); handle.current = undefined }
  }, [graph, labels])
  useEffect(() => { handle.current?.updateSelection(selection) }, [selection])
  return <div className="cart-scene-wrap">
    <div ref={container} className="cart-scene" aria-label={tr('Interactive 3D cartography')} />
    <div className="cart-scene-controls"><span>{tr('Drag to orbit · scroll to zoom · right-drag to pan')}</span><button className="secondary-button" onClick={() => handle.current?.frame()}>{tr('Frame graph')}</button></div>
  </div>
}
