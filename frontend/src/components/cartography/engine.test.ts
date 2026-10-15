// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as THREE from 'three'
import { createScene } from './engine'
import { buildGraph } from './model'
import type { NetworkRelation, NetworkRelations } from '@/api/network'

const renderer = vi.hoisted(() => ({ dispose: vi.fn(), forceContextLoss: vi.fn(), render: vi.fn(), pixelRatio: vi.fn(), canvases: [] as HTMLCanvasElement[], cameras: [] as unknown[], scenes: [] as unknown[] }))
vi.mock('three', async importOriginal => {
  const actual = await importOriginal<typeof import('three')>()
  return { ...actual, WebGLRenderer: class {
    domElement = document.createElement('canvas')
    constructor() { renderer.canvases.push(this.domElement) }
    setPixelRatio = renderer.pixelRatio
    setClearColor() {}
    setSize() {}
    render(scene: THREE.Scene, camera: THREE.Camera) { scene.updateMatrixWorld(); camera.updateMatrixWorld(); renderer.cameras.push(camera); renderer.scenes.push(scene); renderer.render(scene, camera) }
    dispose = renderer.dispose
    forceContextLoss = renderer.forceContextLoss
  } }
})
const rows = (length: number): NetworkRelations => ({ hours: 24, protocol: null, items: Array.from({ length }, (_, i): NetworkRelation => ({ source_ip: '192.0.2.1', domain: `domain-${i}.test`, catalog_match_id: 'catalog-1', protocol: 'TLS', observations: 1, first_seen: '2026-10-15T00:00:00Z', last_seen: '2026-10-15T01:00:00Z' })), total_relations: length, total_observations: length, represented_relations: length, represented_observations: length, truncated: false, limitations: [] })
let frames = new Map<number, FrameRequestCallback>(), next = 0
const disconnect = vi.fn()
function host(width = 800) {
  const container = document.createElement('div'); document.body.append(container)
  Object.defineProperties(container, { clientWidth: { value: width }, clientHeight: { value: 440 } })
  return container
}
function flush() { const queued = [...frames.values()]; frames.clear(); queued.forEach(callback => callback(0)) }
beforeEach(() => {
  vi.clearAllMocks(); renderer.canvases.length = 0; renderer.cameras.length = 0; renderer.scenes.length = 0; frames = new Map(); next = 0
  Object.defineProperty(document, 'hidden', { configurable: true, value: false })
  vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => { frames.set(++next, callback); return next })
  vi.stubGlobal('cancelAnimationFrame', (id: number) => frames.delete(id))
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect = disconnect })
})
afterEach(() => { document.body.replaceChildren(); vi.unstubAllGlobals(); vi.restoreAllMocks() })
describe('on-demand Three resources and bounded camera geometry', () => {
  it('draws once when dirty, has no idle/reduced-motion animation and disposes shared GPU resources idempotently', () => {
    const geometry = vi.spyOn(THREE.BufferGeometry.prototype, 'dispose'), material = vi.spyOn(THREE.Material.prototype, 'dispose')
    const container = host(), graph = buildGraph(rows(2), [], [], { kind: 'all', category: '', search: '' })
    const scene = createScene(container, graph, new Map(), vi.fn(), vi.fn())
    expect(frames.size).toBe(1); flush(); expect(renderer.render).toHaveBeenCalledOnce(); expect(frames.size).toBe(0)
    scene.updateSelection({ kind: 'edge', id: graph.edges[0].id }); flush(); expect(renderer.render).toHaveBeenCalledTimes(2); expect(frames.size).toBe(0)
    scene.frame(); expect(frames.size).toBe(1)
    scene.dispose(); scene.dispose()
    expect(frames.size).toBe(0); expect(disconnect).toHaveBeenCalledOnce(); expect(renderer.dispose).toHaveBeenCalledOnce(); expect(renderer.forceContextLoss).toHaveBeenCalledOnce()
    expect(geometry).toHaveBeenCalledTimes(7) // Four shared node geometries, two curves and grid.
    expect(material).toHaveBeenCalledTimes(9) // Four node, selected, three line, grid materials.
    expect(container.children).toHaveLength(0)
  })
  it('keeps dense parallel curves bounded, removes fog and puts maximum legal zoom inside the far plane on a narrow viewport', () => {
    const container = host(240), graph = buildGraph(rows(500), [], [], { kind: 'all', category: '', search: '' })
    const handle = createScene(container, graph, new Map(), vi.fn(), vi.fn()); flush()
    const scene = renderer.scenes[0] as THREE.Scene, camera = renderer.cameras[0] as THREE.PerspectiveCamera
    expect(scene.fog).toBeNull()
    const lines = scene.children.filter(child => child.type === 'Line') as THREE.Line[]
    expect(lines).toHaveLength(320)
    for (const line of lines) {
      const positions = line.geometry.getAttribute('position')
      for (let i = 0; i < positions.count; i++) expect(Math.abs(positions.getZ(i))).toBeLessThan(60)
    }
    const centerDistance = camera.position.length()
    expect(camera.far).toBeGreaterThan(centerDistance * 1.5)
    handle.dispose()
    const large = rows(500); large.items = large.items.map((row, i) => ({ ...row, source_ip: `source-${i}` }))
    const crowded = buildGraph(large, [], [], { kind: 'all', category: '', search: '' })
    const crowdedHandle = createScene(container, crowded, new Map(), vi.fn(), vi.fn()); flush()
    const crowdedCamera = renderer.cameras.at(-1) as THREE.PerspectiveCamera
    expect(crowded.nodes).toHaveLength(160)
    expect(crowdedCamera.far).toBeGreaterThan(crowdedCamera.position.length() * 1.5)
    crowdedHandle.dispose()
  })
  it('releases partial initialization when an observer fails and does not leave labels or canvases', () => {
    vi.stubGlobal('ResizeObserver', class { observe() { throw new Error('observer unavailable') } disconnect = disconnect })
    const container = host(), graph = buildGraph(rows(1), [], [], { kind: 'all', category: '', search: '' })
    expect(() => createScene(container, graph, new Map(), vi.fn(), vi.fn())).toThrow('observer unavailable')
    expect(disconnect).toHaveBeenCalledOnce(); expect(renderer.dispose).toHaveBeenCalledOnce(); expect(container.children).toHaveLength(0); expect(frames.size).toBe(0)
  })
  it('falls back on render failure and context loss without retaining render work', () => {
    const container = host(), graph = buildGraph(rows(1), [], [], { kind: 'all', category: '', search: '' }), fail = vi.fn()
    renderer.render.mockImplementationOnce(() => { throw new Error('context unavailable') })
    createScene(container, graph, new Map(), vi.fn(), fail); flush()
    expect(fail).toHaveBeenCalledOnce(); expect(renderer.dispose).toHaveBeenCalledOnce(); expect(container.children).toHaveLength(0)
    const handle = createScene(container, graph, new Map(), vi.fn(), fail)
    const event = new Event('webglcontextlost', { cancelable: true }); renderer.canvases.at(-1)!.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(true); expect(fail).toHaveBeenCalledTimes(2)
    handle.dispose(); expect(frames.size).toBe(0)
  })
})
