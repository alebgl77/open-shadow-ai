import type { Plugin, ResolvedConfig, UserConfig } from 'vite'

type Options = Record<string, unknown>
const securedConfigs = new WeakSet<ResolvedConfig>()
const securedBuilds = new WeakSet<object>()

function snapshot(value: unknown, label: string): Options {
  if (value === undefined) return {}
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new Error(`${label} must be a plain options object or null when disabled`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (Object.values(descriptors).some(descriptor => !('value' in descriptor))) {
    throw new Error(`${label} must contain data options, not accessors`)
  }
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]))
}

function literalOptions(value: unknown, label: string): Options {
  const options = snapshot(value, label)
  if (Object.hasOwn(options, 'disableGlobbing') && options.disableGlobbing !== true) {
    throw new Error(`${label}.disableGlobbing must be true; glob expansion is disabled`)
  }
  return { ...options, disableGlobbing: true }
}

function buildWatchPolicy(value: unknown, label: string): Options | null {
  if (value == null) return null
  const watch = snapshot(value, label)
  watch.chokidar = literalOptions(watch.chokidar, `${label}.chokidar`)
  return watch
}

export function normalizeWatchPolicy(config: Pick<UserConfig, 'server' | 'build'>): Pick<UserConfig, 'server' | 'build'> {
  const serverWatch = config.server?.watch === null ? null : literalOptions(config.server?.watch, 'server.watch')
  const buildWatch = buildWatchPolicy(config.build?.watch, 'build.watch')
  return { server: { watch: serverWatch }, build: { watch: buildWatch } } as Pick<UserConfig, 'server' | 'build'>
}

function lock(object: object, key: string, value: unknown) {
  Object.defineProperty(object, key, { value, enumerable: true, writable: false, configurable: false })
}

function secureBuild(build: ResolvedConfig['build'], label: string): void {
  if (securedBuilds.has(build)) return
  const watch = buildWatchPolicy(build.watch, `${label}.watch`)
  if (watch) {
    const chokidar = watch.chokidar as Options
    lock(chokidar, 'disableGlobbing', true)
    lock(watch, 'chokidar', chokidar)
  }
  lock(build, 'watch', watch)
  securedBuilds.add(build)
}

export function secureResolvedWatchPolicy(config: ResolvedConfig): void {
  if (securedConfigs.has(config)) return
  const policy = normalizeWatchPolicy(config)
  const serverWatch = policy.server!.watch
  if (serverWatch) lock(serverWatch, 'disableGlobbing', true)
  lock(config.server, 'watch', serverWatch)
  secureBuild(config.build, 'build')
  // configResolved hooks run concurrently. Lock the reference chain as well as
  // the flags so an awaited late hook cannot replace the protected options.
  lock(config, 'server', config.server)
  lock(config, 'build', config.build)
  // BuildEnvironment reads environment.config.build through an options proxy.
  // Protect each resolved environment, including its map reference, too.
  for (const [name, environment] of Object.entries(config.environments)) {
    secureBuild(environment.build, `environments.${name}.build`)
    lock(environment, 'build', environment.build)
    lock(config.environments, name, environment)
  }
  Object.preventExtensions(config.environments)
  lock(config, 'environments', config.environments)
  securedConfigs.add(config)
}

export function literalWatchPolicy(): Plugin {
  return {
    name: 'literal-file-watch-policy',
    enforce: 'post',
    config(config) {
      const policy = normalizeWatchPolicy(config)
      for (const [name, environment] of Object.entries(config.environments ?? {})) {
        buildWatchPolicy(environment.build?.watch, `environments.${name}.build.watch`)
      }
      // Vite concatenates arrays when merging hook results. Return only policy
      // fields, preserving include/ignored arrays and other plugin options.
      return {
        server: { watch: policy.server!.watch === null ? null : { disableGlobbing: true } },
        build: { watch: policy.build!.watch === null ? null : { chokidar: { disableGlobbing: true } } },
      }
    },
    configResolved: { order: 'post', handler: secureResolvedWatchPolicy },
  }
}
