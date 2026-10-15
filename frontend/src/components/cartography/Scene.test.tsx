// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Scene from './Scene'
import type { Graph } from './model'
const engine = vi.hoisted(() => ({ createScene: vi.fn(), dispose: vi.fn(), frame: vi.fn(), updateSelection: vi.fn() }))
vi.mock('./engine', () => ({ createScene: engine.createScene }))
const graph: Graph = { nodes: [], edges: [], eligibleNodes: 0, eligibleEdges: 0, omittedNodes: 0, omittedEdges: 0, representedObservations: 0, representedInstallations: 0 }
afterEach(() => { cleanup(); vi.clearAllMocks() })
describe('lazy WebGL lifecycle boundary', () => {
  it('frames manually, updates selection without rebuilding, and disposes once on unmount', async () => {
    engine.createScene.mockReturnValue(engine)
    const labels = new Map<string, string>(), onSelect = vi.fn(), onUnavailable = vi.fn()
    const result = render(<Scene graph={graph} labels={labels} selection={null} onSelect={onSelect} onUnavailable={onUnavailable}/>)
    await waitFor(() => expect(engine.createScene).toHaveBeenCalledTimes(1))
    fireEvent.click(screen.getByRole('button', { name: 'Frame graph' }))
    expect(engine.frame).toHaveBeenCalledOnce()
    result.rerender(<Scene graph={graph} labels={labels} selection={{ kind: 'node', id: 'node' }} onSelect={onSelect} onUnavailable={onUnavailable}/>)
    expect(engine.updateSelection).toHaveBeenLastCalledWith({ kind: 'node', id: 'node' })
    expect(engine.createScene).toHaveBeenCalledTimes(1)
    result.unmount(); expect(engine.dispose).toHaveBeenCalledOnce()
  })
  it('does not create a renderer after a deferred import resolves on a detached/unmounted component', async () => {
    engine.createScene.mockReturnValue(engine)
    const result = render(<Scene graph={graph} labels={new Map()} selection={null} onSelect={() => {}} onUnavailable={() => {}}/>)
    result.unmount(); await act(async () => {})
    expect(engine.createScene).not.toHaveBeenCalled()
    expect(engine.dispose).not.toHaveBeenCalled()
  })
  it('signals the usable list fallback when renderer initialization fails', async () => {
    engine.createScene.mockImplementation(() => { throw new Error('WebGL2 unavailable') })
    const onUnavailable = vi.fn()
    render(<Scene graph={graph} labels={new Map()} selection={null} onSelect={() => {}} onUnavailable={onUnavailable}/>)
    await waitFor(() => expect(onUnavailable).toHaveBeenCalledOnce())
  })
})
