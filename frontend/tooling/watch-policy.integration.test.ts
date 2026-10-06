// @vitest-environment node
import { EventEmitter } from 'node:events'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { build, createServer, normalizePath } from 'vite'
import type { Plugin, ViteDevServer } from 'vite'
import type { RollupWatcher, RollupWatcherEvent } from 'rollup'
import { literalWatchPolicy, normalizeWatchPolicy } from './watch-policy'

const timeout = 8000
const literalWatchOptions = { ignoreInitial: false, usePolling: false, atomic: false }

async function bounded<T>(work: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([work, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), timeout)
    })])
  } finally {
    clearTimeout(timer)
  }
}

function event(emitter: EventEmitter, name: string, expected: string) {
  let cleanup = () => {}
  return bounded(new Promise<string>((resolveEvent, reject) => {
    cleanup = () => { emitter.off(name, listener); emitter.off('error', onError) }
    const listener = (file: string) => {
      if (resolve(file) === expected) { cleanup(); resolveEvent(file) }
    }
    const onError = (error: Error) => { cleanup(); reject(error) }
    emitter.on(name, listener)
    emitter.on('error', onError)
  }), `${name} for ${expected}`).finally(() => cleanup())
}

async function waitFor(condition: () => boolean | Promise<boolean>, label: string, state: () => unknown) {
  const deadline = Date.now() + timeout
  while (!(await condition())) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${label}; state=${JSON.stringify(state())}`)
    await new Promise(done => setTimeout(done, 20))
  }
}

async function fixture() {
  const prefix = join(tmpdir(), 'shadai-literal-watch-')
  const directory = await mkdtemp(prefix)
  const root = join(directory, 'project')
  await mkdir(root)
  await writeFile(join(root, 'index.html'), '<script type="module" src="/main.js"></script>')
  await writeFile(join(root, 'main.js'), 'console.log("initial-watch-marker"); if (import.meta.hot) import.meta.hot.accept()')
  return {
    directory, root,
    async cleanup() {
      if (!directory.startsWith(prefix)) throw new Error('Unexpected fixture cleanup path')
      await bounded(rm(directory, { recursive: true, force: true }), 'fixture cleanup')
    },
  }
}

function watchedFiles(watcher: ViteDevServer['watcher'], directory: string): string[] {
  const entry = Object.entries(watcher.getWatched()).find(([path]) => resolve(path) === directory)
  return entry?.[1] ?? []
}

async function bundleEnd(watcher: RollupWatcher) {
  let listener: (result: RollupWatcherEvent) => void
  try {
    await bounded(new Promise<void>((resolveBuild, reject) => {
      listener = result => {
        if (result.code === 'ERROR') reject(result.error)
        if (result.code === 'BUNDLE_END') result.result.close().then(() => resolveBuild(), reject)
      }
      watcher.on('event', listener)
    }), 'BUNDLE_END')
  } finally {
    watcher.off('event', listener!)
  }
}

async function output(directory: string) {
  const assets = join(directory, 'assets')
  const files = (await readdir(assets)).filter(file => file.endsWith('.js'))
  return (await Promise.all(files.map(file => readFile(join(assets, file), 'utf8')))).join('\n')
}

async function publicWatcher(engine: string, safe: boolean, root: string) {
  if (engine === 'vite') {
    const server = await createServer({
      configFile: false, root, logLevel: 'silent', plugins: safe ? [literalWatchPolicy()] : [],
      server: { middlewareMode: true, ws: false, watch: safe ? literalWatchOptions : { ...literalWatchOptions, disableGlobbing: false } },
    })
    return { watcher: server.watcher, close: () => server.close() }
  }
  // Rollup embeds chokidar in a private distribution module. This exercises its
  // watch/add API as installed, without copying or modifying vendor source.
  const require = createRequire(import.meta.url)
  const rollupPath = join(dirname(require.resolve('rollup')), 'shared/index.js')
  const { chokidar } = require(rollupPath)
  const options = safe
    ? normalizeWatchPolicy({ build: { watch: { chokidar: literalWatchOptions } } }).build!.watch!.chokidar
    : { ...literalWatchOptions, disableGlobbing: false }
  const watcher: ViteDevServer['watcher'] = chokidar.watch(root, options)
  return { watcher, close: () => watcher.close() }
}

describe('literal watch policy with real filesystem watchers', () => {
  it('routes a real module edit through HMR and invalidates its cached transform', async () => {
    const files = await fixture()
    let server: ViteDevServer | undefined
    const entry = join(files.root, 'main.js')
    type Update = { file: string, modules: string[] }
    const updates: Update[] = []
    let notifyUpdate = (_update: Update) => {}
    const observeHmr: Plugin = { name: 'observe-real-hmr', handleHotUpdate(context) {
      const update = { file: resolve(context.file), modules: context.modules.map(module => module.url) }
      updates.push(update)
      notifyUpdate(update)
    } }
    try {
      server = await createServer({
        configFile: false, root: files.root, logLevel: 'silent', plugins: [literalWatchPolicy(), observeHmr],
        server: { middlewareMode: true, ws: false, watch: literalWatchOptions },
      })
      await waitFor(() => watchedFiles(server!.watcher, files.root).includes('main.js'), `watch enrollment of ${entry}`, () => server!.watcher.getWatched())
      expect((await server.transformRequest('/main.js'))?.code).toContain('initial-watch-marker')
      const module = await server.environments.client.moduleGraph.getModuleByUrl('/main.js')
      expect(module?.transformResult?.code).toContain('initial-watch-marker')
      const hotUpdate = bounded(new Promise<Update>(resolveUpdate => {
        notifyUpdate = update => {
          if (update.file === entry && update.modules.includes('/main.js')) resolveUpdate(update)
        }
      }), `HMR for ${entry}, expected /main.js`)
      await writeFile(entry, 'console.log("updated-watch-marker"); if (import.meta.hot) import.meta.hot.accept()')
      expect(await hotUpdate).toMatchObject({ file: entry, modules: expect.arrayContaining(['/main.js']) })
      await waitFor(() => module?.transformResult === null, `cached module invalidation for ${normalizePath(entry)}`, () => ({ updates, transformed: module?.transformResult?.code }))
      expect((await server.transformRequest('/main.js'))?.code).toContain('updated-watch-marker')
    } finally {
      if (server) await bounded(server.close(), 'dev server close')
      await files.cleanup()
    }
  }, 25000)

  it('rebuilds an opted-in Rollup watch build after a real entry edit', async () => {
    const files = await fixture()
    let watcher: RollupWatcher | undefined
    const outDir = join(files.directory, 'dist')
    try {
      const result = await build({ configFile: false, root: files.root, logLevel: 'silent', plugins: [literalWatchPolicy()],
        build: { outDir, watch: { chokidar: { usePolling: true, interval: 40 } } },
      })
      if (!('on' in result)) throw new Error('Expected a real Rollup watcher')
      watcher = result
      await bundleEnd(watcher)
      expect(await output(outDir)).toContain('initial-watch-marker')
      const rebuilt = bundleEnd(watcher)
      await writeFile(join(files.root, 'main.js'), 'console.log("rebuilt-watch-marker")')
      await rebuilt
      expect(await output(outDir)).toContain('rebuilt-watch-marker')
    } finally {
      if (watcher) await bounded(watcher.close(), 'build watcher close')
      await files.cleanup()
    }
  }, 25000)

  it('finishes a default production build without returning a watcher', async () => {
    const files = await fixture()
    const outDir = join(files.directory, 'dist')
    try {
      const result = await bounded(build({ configFile: false, root: files.root, logLevel: 'silent',
        plugins: [literalWatchPolicy()], build: { outDir },
      }), 'production build')
      expect('on' in result).toBe(false)
      expect(await output(outDir)).toContain('initial-watch-marker')
    } finally {
      await files.cleanup()
    }
  }, 15000)

  it.each(['vite', 'rollup'])('preserves literal add/change with the %s watcher policy and a benign glob control', async engine => {
    const files = await fixture()
    try {
      for (const safe of [false, true]) {
        const external = join(files.directory, safe ? 'safe-external' : 'glob-external')
        await mkdir(external)
        const literal = join(external, 'probe{one,two}.js')
        const alternatives = ['probeone.js', 'probetwo.js']
        for (const name of ['probe{one,two}.js', ...alternatives]) await writeFile(join(external, name), 'initial')
        const actual = await publicWatcher(engine, safe, files.root)
        try {
          if (safe) {
            const added = event(actual.watcher, 'add', literal)
            actual.watcher.add(literal)
            await added
            expect(watchedFiles(actual.watcher, external)).toContain('probe{one,two}.js')
            for (const alternative of alternatives) expect(watchedFiles(actual.watcher, external)).not.toContain(alternative)
            const changed = event(actual.watcher, 'change', literal)
            await writeFile(literal, 'updated-literal-value')
            await changed
            for (const alternative of alternatives) expect(watchedFiles(actual.watcher, external)).not.toContain(alternative)
          } else {
            // Globbing matches exact literal strings as well as brace-expanded names.
            const expectedNames = [basename(literal), ...alternatives]
            const added = expectedNames.map(name => event(actual.watcher, 'add', join(external, name)))
            actual.watcher.add(literal)
            await Promise.all(added)
            expect(watchedFiles(actual.watcher, external)).toEqual(expect.arrayContaining(expectedNames))
            const changed = event(actual.watcher, 'change', join(external, alternatives[0]))
            await writeFile(join(external, alternatives[0]), 'updated-glob-control-value')
            await changed
          }
        } finally {
          await bounded(actual.close(), `${engine} public watcher close`)
        }
      }
    } finally {
      await files.cleanup()
    }
  }, 25000)
})
