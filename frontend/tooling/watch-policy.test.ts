import { describe, expect, it } from 'vitest'
import { createServer, resolveConfig } from 'vite'
import type { Plugin, ResolvedConfig, UserConfig } from 'vite'
import { literalWatchPolicy, normalizeWatchPolicy, secureResolvedWatchPolicy } from './watch-policy'

describe('literal watch policy', () => {
  it('keeps disabled watchers and default production build disabled', async () => {
    expect(normalizeWatchPolicy({}).build?.watch).toBeNull()
    const config = await resolveConfig({ configFile: false, plugins: [literalWatchPolicy()], server: { watch: null } }, 'build')
    expect(config.server.watch).toBeNull()
    expect(config.build.watch).toBeNull()
    expect(() => secureResolvedWatchPolicy(config)).not.toThrow()
  })

  it('preserves literal watcher options and functions while securing omitted flags', async () => {
    const ignored = (file: string) => file.endsWith('.bak')
    const config = await resolveConfig({
      configFile: false, plugins: [literalWatchPolicy()],
      server: { watch: { ignored, usePolling: true, interval: 40 } },
      build: { watch: { include: ['src/**'], exclude: ['dist/**'], chokidar: { ignored, awaitWriteFinish: { stabilityThreshold: 60, pollInterval: 10 } } } },
    }, 'build')
    expect(config.server.watch?.ignored).toBe(ignored)
    expect(config.server.watch?.interval).toBe(40)
    expect(config.build.watch?.include).toEqual(['src/**'])
    expect(config.build.watch?.exclude).toEqual(['dist/**'])
    expect(config.build.watch?.chokidar?.ignored).toBe(ignored)
    expect(config.build.watch?.chokidar?.awaitWriteFinish).toEqual({ stabilityThreshold: 60, pollInterval: 10 })
    expect(() => secureResolvedWatchPolicy(config)).not.toThrow()
  })

  it('preserves ignored lists without a second merge', async () => {
    const config = await resolveConfig({
      configFile: false, plugins: [literalWatchPolicy()],
      server: { watch: { ignored: ['**/*.bak'] } },
      build: { watch: { chokidar: { ignored: ['**/*.bak'] } } },
    }, 'build')
    expect(config.server.watch?.ignored).toEqual(['**/*.bak'])
    expect(config.build.watch?.chokidar?.ignored).toEqual(['**/*.bak'])
    expect(config.environments.client.build.watch?.chokidar?.ignored).toEqual(['**/*.bak'])
  })

  it.each([false, undefined, null, 0, 'true'])('rejects an explicit unsafe dev flag %s before server construction', async flag => {
    const config = { configFile: false, plugins: [literalWatchPolicy()], server: { watch: { disableGlobbing: flag } } } as unknown as UserConfig
    await expect(createServer(config)).rejects.toThrow(/disableGlobbing must be true/)
  })

  it.each([false, undefined, null, 0, 'true'])('rejects an explicit unsafe opted-in build flag %s', async flag => {
    const config = { configFile: false, plugins: [literalWatchPolicy()], build: { watch: { chokidar: { disableGlobbing: flag } } } } as unknown as UserConfig
    await expect(resolveConfig(config, 'build')).rejects.toThrow(/disableGlobbing must be true/)
  })

  it.each([false, [], 'watch', 3])('rejects unsupported watcher options %s', value => {
    expect(() => normalizeWatchPolicy({ server: { watch: value } } as unknown as UserConfig)).toThrow(/plain options object/)
    expect(() => normalizeWatchPolicy({ build: { watch: value } } as unknown as UserConfig)).toThrow(/plain options object/)
  })

  it('rejects accessor-based options without invoking the getter', () => {
    let invoked = false
    const watch = Object.defineProperty({}, 'disableGlobbing', { get: () => { invoked = true; return true } })
    expect(() => normalizeWatchPolicy({ server: { watch } })).toThrow(/not accessors/)
    expect(invoked).toBe(false)
  })

  const mutations: [string, (config: ResolvedConfig) => void][] = [
    ['server parent', config => { config.server = { ...config.server, watch: { disableGlobbing: false } } }],
    ['build parent', config => { config.build = { ...config.build, watch: { chokidar: { disableGlobbing: false } } } }],
    ['dev watch reference', config => { config.server.watch = { disableGlobbing: false } }],
    ['build watch reference', config => { config.build.watch = { chokidar: { disableGlobbing: false } } }],
    ['build chokidar reference', config => { config.build.watch!.chokidar = { disableGlobbing: false } }],
    ['dev flag assignment', config => { config.server.watch!.disableGlobbing = false }],
    ['build flag assignment', config => { config.build.watch!.chokidar!.disableGlobbing = false }],
    ['flag deletion', config => { delete config.server.watch!.disableGlobbing }],
    ['flag redefinition', config => { Object.defineProperty(config.server.watch!, 'disableGlobbing', { value: false }) }],
  ]
  it.each(mutations)('rejects awaited late mutation of %s during real config resolution', async (_, mutate) => {
    const earlierAsync: Plugin = { name: 'awaited-unsafe-mutation', async configResolved(config) { await new Promise(resolve => setTimeout(resolve, 0)); mutate(config) } }
    await expect(resolveConfig({ configFile: false, plugins: [earlierAsync, literalWatchPolicy()], build: { watch: {} } }, 'build')).rejects.toThrow(TypeError)
  })

  it.each([false, undefined, null, 0, 'true'])('rejects an explicit unsafe environment flag %s', async flag => {
    const config = {
      configFile: false, plugins: [literalWatchPolicy()],
      environments: { custom: { build: { watch: { chokidar: { disableGlobbing: flag } } } } },
    } as unknown as UserConfig
    await expect(resolveConfig(config, 'build')).rejects.toThrow(/environments.custom.build.watch.chokidar.disableGlobbing must be true/)
  })

  const environmentMutations: [string, (config: ResolvedConfig) => void][] = [
    ['environments map', config => { config.environments = {} }],
    ['environment reference', config => { config.environments.client = { ...config.environments.client, build: { ...config.environments.client.build, watch: { chokidar: { disableGlobbing: false } } } } }],
    ['environment addition', config => { config.environments.unsafe = { ...config.environments.client } }],
    ['environment deletion', config => { delete config.environments.client }],
    ['environment build', config => { config.environments.client.build = { ...config.environments.client.build, watch: { chokidar: { disableGlobbing: false } } } }],
    ['environment watch', config => { config.environments.client.build.watch = { chokidar: { disableGlobbing: false } } }],
    ['environment chokidar', config => { config.environments.client.build.watch!.chokidar = { disableGlobbing: false } }],
    ['environment flag', config => { config.environments.client.build.watch!.chokidar!.disableGlobbing = false }],
  ]
  it.each(environmentMutations)('rejects awaited late mutation of %s', async (_, mutate) => {
    const earlierAsync: Plugin = { name: 'awaited-environment-mutation', async configResolved(config) {
      await new Promise(resolve => setTimeout(resolve, 0))
      mutate(config)
    } }
    await expect(resolveConfig({ configFile: false, plugins: [earlierAsync, literalWatchPolicy()], build: { watch: {} } }, 'build')).rejects.toThrow(TypeError)
  })

  it('rejects unsafe watch settings introduced by configEnvironment', async () => {
    const unsafeEnvironment: Plugin = { name: 'unsafe-environment', configEnvironment() {
      return { build: { watch: { chokidar: { disableGlobbing: false } } } }
    } }
    await expect(resolveConfig({ configFile: false, plugins: [unsafeEnvironment, literalWatchPolicy()] }, 'build')).rejects.toThrow(/disableGlobbing must be true/)
  })

  it('detaches captured old watch objects before awaited mutations', async () => {
    const earlierAsync: Plugin = { name: 'captured-watch', async configResolved(config) {
      const serverWatch = config.server.watch!
      const buildWatch = config.environments.client.build.watch!
      await new Promise(resolve => setTimeout(resolve, 0))
      serverWatch.disableGlobbing = false
      buildWatch.chokidar = { disableGlobbing: false }
    } }
    const config = await resolveConfig({ configFile: false, plugins: [earlierAsync, literalWatchPolicy()], build: { watch: {} } }, 'build')
    expect(config.server.watch?.disableGlobbing).toBe(true)
    expect(config.environments.client.build.watch?.chokidar?.disableGlobbing).toBe(true)
  })

  it('secures aliased root/environment build options once', async () => {
    const aliasBuild: Plugin = { name: 'alias-build', configResolved(config) { config.environments.client.build = config.build } }
    const config = await resolveConfig({ configFile: false, plugins: [aliasBuild, literalWatchPolicy()], build: { watch: {} } }, 'build')
    expect(config.environments.client.build).toBe(config.build)
    expect(config.environments.client.build.watch?.chokidar?.disableGlobbing).toBe(true)
  })

  it('allows awaited unrelated option updates', async () => {
    const benign: Plugin = { name: 'benign-async', async configResolved(config) {
      await Promise.resolve()
      config.server.host = '127.0.0.1'
      config.build.sourcemap = true
      config.environments.client.build.sourcemap = true
      config.environments.client.resolve.alias.push({ find: 'test', replacement: '/test' })
    } }
    const config = await resolveConfig({ configFile: false, plugins: [benign, literalWatchPolicy()], build: { watch: {} } }, 'build')
    expect(config.server.host).toBe('127.0.0.1')
    expect(config.build.sourcemap).toBe(true)
    expect(config.environments.client.build.sourcemap).toBe(true)
    expect(config.environments.client.resolve.alias).toContainEqual({ find: 'test', replacement: '/test' })
  })
})
