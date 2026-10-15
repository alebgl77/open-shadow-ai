import * as THREE from 'three'
import { OrbitControls } from 'three/addons/controls/OrbitControls.js'
import { curveOffset, type Graph, type NodeKind, type Selection } from './model'

export const NODE_COLORS: Record<NodeKind, string> = { ip: '#65dbc6', host: '#8fb9ef', service: '#e5c087', unmatched: '#8a9aa8' }
export interface SceneHandle { dispose: () => void; frame: () => void; updateSelection: (selection: Selection) => void }

/** One scheduled frame per invalidation; no force simulation or idle animation. */
export function createScene(container: HTMLDivElement, graph: Graph, labels: Map<string, string>, select: (selection: Selection) => void, fail: () => void): SceneHandle {
  const cleanup: Array<() => void> = []
  let disposed = false, raf = 0
  const dispose = () => {
    if (disposed) return
    disposed = true; cancelAnimationFrame(raf)
    // Partial initialization must release resources just like a normal unmount.
    for (const release of cleanup.reverse()) { try { release() } catch { /* Continue releasing independent resources. */ } }
    cleanup.length = 0
  }
  try {
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'low-power' })
    cleanup.push(() => { renderer.dispose(); renderer.forceContextLoss(); renderer.domElement.remove() })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5))
    renderer.setClearColor('#0b151a')
    renderer.domElement.setAttribute('aria-hidden', 'true')
    renderer.domElement.style.touchAction = 'none'
    container.append(renderer.domElement)
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(38, 1, .1, 800)
    const controls = new OrbitControls(camera, renderer.domElement)
    cleanup.push(() => controls.dispose())
    controls.enableDamping = false; controls.minDistance = 30; controls.maxDistance = 430
    controls.maxPolarAngle = Math.PI * .92
    scene.add(new THREE.AmbientLight('#c7e5f0', 1.8))
    const light = new THREE.DirectionalLight('#d6fff6', 2.8); light.position.set(0, 80, 90); scene.add(light)
    const grid = new THREE.GridHelper(360, 24, '#284349', '#14292e'); grid.position.y = -80; scene.add(grid)
    cleanup.push(() => { grid.geometry.dispose(); (Array.isArray(grid.material) ? grid.material : [grid.material]).forEach(material => material.dispose()) })
    const geometries = { ip: new THREE.SphereGeometry(3.2, 18, 12), host: new THREE.BoxGeometry(6, 6, 6), service: new THREE.OctahedronGeometry(4.6), unmatched: new THREE.IcosahedronGeometry(2.8) }
    cleanup.push(() => Object.values(geometries).forEach(geometry => geometry.dispose()))
    const materials = new Map<NodeKind, THREE.MeshStandardMaterial>()
    cleanup.push(() => materials.forEach(material => material.dispose()))
    for (const kind of Object.keys(NODE_COLORS) as NodeKind[]) materials.set(kind, new THREE.MeshStandardMaterial({ color: NODE_COLORS[kind], emissive: NODE_COLORS[kind], emissiveIntensity: .14, roughness: .45, metalness: .2 }))
    const selectedMaterial = new THREE.MeshStandardMaterial({ color: '#ffffff', emissive: '#65dbc6', emissiveIntensity: .6, roughness: .4 })
    cleanup.push(() => selectedMaterial.dispose())
    const meshes = new Map<string, THREE.Mesh>()
    const labelElements = new Map<string, HTMLSpanElement>()
    const labelLeaders = new Map<string, HTMLSpanElement>()
    cleanup.push(() => { labelElements.forEach(element => element.remove()); labelLeaders.forEach(element => element.remove()); labelElements.clear(); labelLeaders.clear(); meshes.clear(); scene.clear() })
    for (const node of graph.nodes) {
      const mesh = new THREE.Mesh(geometries[node.kind], materials.get(node.kind))
      mesh.position.set(...node.position); mesh.userData.selection = { kind: 'node', id: node.id }; scene.add(mesh); meshes.set(node.id, mesh)
      const label = document.createElement('span')
      label.className = 'cart-scene-label'; label.textContent = labels.get(node.id) || node.label
      label.dataset.kind = node.kind; label.setAttribute('aria-hidden', 'true')
      container.append(label); labelElements.set(node.id, label)
      const leader = document.createElement('span'); leader.className = 'cart-label-leader'; leader.setAttribute('aria-hidden', 'true'); leader.hidden = true
      container.append(leader); labelLeaders.set(node.id, leader)
    }
    const lineGeometries: THREE.BufferGeometry[] = []
    cleanup.push(() => lineGeometries.forEach(geometry => geometry.dispose()))
    const lineMaterials = [new THREE.LineBasicMaterial({ color: '#65dbc6', transparent: true, opacity: .38 }), new THREE.LineBasicMaterial({ color: '#8fb9ef', transparent: true, opacity: .4 }), new THREE.LineBasicMaterial({ color: '#dcfff6', transparent: true, opacity: .95 })]
    cleanup.push(() => lineMaterials.forEach(material => material.dispose()))
    const lines = new Map<string, THREE.Line>()
    const parallel = new Map<string, number>()
    const framePoints = graph.nodes.map(node => new THREE.Vector3(...node.position))
    for (const edge of graph.edges) {
      const source = meshes.get(edge.source)!.position, target = meshes.get(edge.target)!.position
      const key = JSON.stringify([edge.source, edge.target])
      const ordinal = parallel.get(key) || 0; parallel.set(key, ordinal + 1)
      const [offsetY, offsetZ] = curveOffset(ordinal)
      const middle = source.clone().lerp(target, .5); middle.z += offsetZ; middle.y += offsetY; framePoints.push(middle)
      const curve = new THREE.QuadraticBezierCurve3(source, middle, target)
      const geometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(30)); lineGeometries.push(geometry)
      const line = new THREE.Line(geometry, lineMaterials[edge.kind === 'network' ? 0 : 1])
      line.userData.selection = { kind: 'edge', id: edge.id }; scene.add(line); lines.set(edge.id, line)
    }
    let selected: Selection = null
    const vector = new THREE.Vector3()
    const render = () => {
      raf = 0
      if (disposed || document.hidden || !container.isConnected) return
      try { renderer.render(scene, camera) } catch { dispose(); fail(); return }
      const selectedIds = new Set<string>()
      if (selected?.kind === 'node') selectedIds.add(selected.id)
      for (const edge of graph.edges) if ((selected?.kind === 'edge' && edge.id === selected.id) || (selected?.kind === 'node' && [edge.source, edge.target].includes(selected.id))) { selectedIds.add(edge.source); selectedIds.add(edge.target) }
      const visibleRects: Array<{ x: number; y: number; width: number }> = []
      const priority = (kind: NodeKind) => kind === 'ip' ? 2 : kind === 'service' ? 1 : 0
      const ordered = [...graph.nodes].sort((a, b) => Number(selectedIds.has(b.id)) - Number(selectedIds.has(a.id)) || priority(b.kind) - priority(a.kind))
      let visibleCount = 0
      for (const node of ordered) {
        const element = labelElements.get(node.id)!
        vector.copy(meshes.get(node.id)!.position).project(camera)
        const nodeX = (vector.x + 1) * container.clientWidth / 2, nodeY = (-vector.y + 1) * container.clientHeight / 2
        const width = Math.min(container.clientWidth < 400 ? 140 : 190, element.textContent!.length * 6.5 + 18)
        const selectedLabel = selectedIds.has(node.id)
        let placed: { x: number; y: number } | undefined
        if (vector.z < 1 && vector.z > -1 && nodeX > 5 && nodeX < container.clientWidth - 5 && nodeY > 5 && nodeY < container.clientHeight - 5 && visibleCount < 24) {
          for (const [dx, dy] of [[0, 17], [0, -23], [0, 42], [0, -48], [-45, 17], [45, 17], [0, 67], [0, -73], [-65, 42], [65, -48]]) {
            const x = Math.max(width / 2 + 6, Math.min(container.clientWidth - width / 2 - 6, nodeX + dx)), y = nodeY + dy
            if (y < 12 || y > container.clientHeight - 24) continue
            if (!visibleRects.some(rect => Math.abs(rect.y - y) < 26 && Math.abs(rect.x - x) < (rect.width + width) / 2 + 6)) { placed = { x, y }; break }
          }
        }
        const visible = !!placed
        element.hidden = !visible
        const leader = labelLeaders.get(node.id)!; leader.hidden = !visible
        element.dataset.selected = String(selectedLabel)
        if (placed) {
          const { x, y } = placed
          visibleCount++; visibleRects.push({ x, y, width }); element.style.left = `${x}px`; element.style.top = `${y}px`
          const dx = x - nodeX, dy = y - nodeY
          leader.style.left = `${nodeX}px`; leader.style.top = `${nodeY}px`; leader.style.width = `${Math.hypot(dx, dy)}px`; leader.style.transform = `rotate(${Math.atan2(dy, dx)}rad)`
        }
      }
    }
    const invalidate = () => { if (!disposed && !raf && !document.hidden) raf = requestAnimationFrame(render) }
    const updateSelection = (value: Selection) => {
      selected = value
      const linked = new Set<string>()
      for (const edge of graph.edges) {
        const active = value?.kind === 'edge' ? value.id === edge.id : value?.kind === 'node' && [edge.source, edge.target].includes(value.id)
        lines.get(edge.id)!.material = lineMaterials[active ? 2 : edge.kind === 'network' ? 0 : 1]
        if (active) { linked.add(edge.source); linked.add(edge.target) }
      }
      for (const node of graph.nodes) {
        const mesh = meshes.get(node.id)!; const active = linked.has(node.id) || (value?.kind === 'node' && value.id === node.id)
        mesh.material = active ? selectedMaterial : materials.get(node.kind)!
        mesh.scale.setScalar(active ? 1.2 : 1)
      }
      invalidate()
    }
    const frame = () => {
      const box = new THREE.Box3().setFromPoints(framePoints)
      const center = graph.nodes.length ? box.getCenter(new THREE.Vector3()) : new THREE.Vector3()
      const size = graph.nodes.length ? box.getSize(new THREE.Vector3()).length() : 140
      // Respect a narrow viewport as well as the vertical camera field of view.
      const distance = Math.max(140, size / (2 * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2))) / Math.min(1, camera.aspect) * .85)
      controls.maxDistance = Math.max(430, distance * 1.5)
      camera.far = Math.max(800, controls.maxDistance + size + 30); camera.updateProjectionMatrix()
      controls.target.copy(center); camera.position.copy(center).add(new THREE.Vector3(30, 42, distance)); controls.update(); invalidate()
    }
    const resize = () => {
      if (disposed) return
      const width = Math.max(1, container.clientWidth), height = Math.max(1, container.clientHeight)
      renderer.setSize(width, height, false); camera.aspect = width / height; camera.updateProjectionMatrix(); invalidate()
    }
    const observer = new ResizeObserver(resize)
    cleanup.push(() => observer.disconnect())
    observer.observe(container)
    controls.addEventListener('change', invalidate)
    cleanup.push(() => controls.removeEventListener('change', invalidate))
    document.addEventListener('visibilitychange', invalidate)
    cleanup.push(() => document.removeEventListener('visibilitychange', invalidate))
    const raycaster = new THREE.Raycaster(); raycaster.params.Line!.threshold = 1.1
    let down: { x: number; y: number } | null = null
    const pointerDown = (event: PointerEvent) => { down = { x: event.clientX, y: event.clientY } }
    const pointerUp = (event: PointerEvent) => {
      if (!down || Math.hypot(down.x - event.clientX, down.y - event.clientY) > 5) { down = null; return }
      down = null
      const rect = renderer.domElement.getBoundingClientRect()
      raycaster.setFromCamera(new THREE.Vector2((event.clientX - rect.left) / rect.width * 2 - 1, -(event.clientY - rect.top) / rect.height * 2 + 1), camera)
      const node = raycaster.intersectObjects([...meshes.values()])[0]
      const hit = node || raycaster.intersectObjects([...lines.values()])[0]
      if (hit) select(hit.object.userData.selection as Selection)
    }
    const contextLost = (event: Event) => { event.preventDefault(); fail() }
    renderer.domElement.addEventListener('pointerdown', pointerDown)
    renderer.domElement.addEventListener('pointerup', pointerUp)
    renderer.domElement.addEventListener('webglcontextlost', contextLost)
    cleanup.push(() => { renderer.domElement.removeEventListener('pointerdown', pointerDown); renderer.domElement.removeEventListener('pointerup', pointerUp); renderer.domElement.removeEventListener('webglcontextlost', contextLost) })
    resize(); frame()
    return { frame, updateSelection, dispose }
  } catch (error) { dispose(); throw error }
}
