# Frontend build security

The frontend uses Tailwind CSS and `@tailwindcss/vite` `4.3.3` with Vite `6.4.4`. This removes Tailwind 3's named vulnerable brace-expansion chain while retaining the application's custom theme. PostCSS nesting/parser overrides are no longer needed. npm generated the lockfile; dependency versions were not falsified and no vendor sources were patched.

## Residual bundled code and watcher policy

[GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) affects `braces` through `3.0.3` and lists no patched release. The named npm nodes `braces`, `chokidar`, `micromatch`, `fast-glob`, `postcss-nested` and `postcss-selector-parser` are absent. Nevertheless, Vite's `dist/node/chunks/dep-3O3b9SCF.js` includes bundled braces/chokidar code. Rollup `4.63.5` has additional copies in `dist/shared/index.js` and `dist/es/shared/watch.js`. Dependency audits do not inventory this inlined source.

In [chokidar's watcher implementation](https://raw.githubusercontent.com/paulmillr/chokidar/3.6.0/index.js), `disableGlobbing` selects literal path handling; `getDirParts` returns before `braces.expand` when `hasGlob` is false. Vite's [server construction](https://github.com/vitejs/vite/blob/v6.4.4/packages/vite/src/node/server/index.ts) lets configured watch options override its default. The application guard in `frontend/tooling/watch-policy.ts` validates options, supplies `disableGlobbing: true` when omitted, and rejects explicit false or other invalid values.

Vite runs `configResolved` hooks concurrently, so hook ordering alone does not prevent a late awaited replacement. The guard locks the relevant flags and the references from `config.server` and `config.build` to their watch options. Actual Vite build environments read their own `environment.config.build`; the guard also locks each resolved environment/build/watch/chokidar chain and prevents adding an unprotected environment afterward. Lists, functions and other normal watch options are retained once, and unrelated existing settings remain mutable.

`server.watch: null` disables dev watching. An omitted or null `build.watch` keeps ordinary production builds finite; opt-in watch builds retain literal file changes and rebuild behavior. Resolved default environment entries and their watcher policy must be configured before resolution. Custom environment factories and later setup overrides require their own review. Late replacement of the protected resolved references fails rather than enabling glob expansion. Rollup's current watcher also forces `disableGlobbing: true` after its option spread; the application does not rely on that behavior alone.

The guard covers these configuration paths before application Vite/Rollup watcher construction with the default environment factories used by the current configuration. Custom `build.createEnvironment` factories or explicit `new BuildEnvironment(..., options)` arguments can create different option objects after resolution and require separate review. Trusted plugins can execute arbitrary Node code, create separate watchers, or modify constructed watcher objects directly; those actions are outside this mitigation. Dependency updates require re-inspection of the actual bundled call path and environment API. Do not treat this guard as general denial-of-service prevention, parser repair or a plugin sandbox.

## Compatibility and build requirements

Use a supported Node version satisfying `frontend/package.json` engines. The authoring host uses Node `22.23.2` and npm `10.9.8`; the mandatory frontend workflow uses Node 22 on Ubuntu ARM. Native Tailwind/Rollup packages require a clean installation on each OS/architecture. The existing Docker build uses Alpine/musl and must also pass independently.

Tailwind 4 requires Safari 16.4+, Chrome 111+ and Firefox 128+ according to its [upgrade guide](https://tailwindcss.com/docs/upgrade-guide). The change raises this browser floor. The existing JavaScript theme is loaded explicitly with `@config`; sources are restricted to `index.html` and application TS/TSX files. Legacy RGB palette values, spacing and divider selectors, radius, focus-outline behavior, fonts and important zero padding are preserved with scoped compatibility declarations and utility renames. Generated CSS changes from the Tailwind 3 baseline; byte identity is no longer an acceptance claim. Static rule comparisons do not establish rendered browser equality.

## Reproduce verification

Run from `frontend` with the repository's supported Node/npm versions:

```sh
npm ci
npm ls --all
npm ls source-map-js braces chokidar micromatch fast-glob postcss-nested postcss-selector-parser --all
npm test
npm run build
npm run lint
npm audit --package-lock-only --include=dev --include=optional --json
rg -n --no-ignore 'braces\S*\.expand|braces\S*\.compile|braces\S*\.parse' node_modules/vite/dist node_modules/rollup/dist
```

`npm audit` sends dependency metadata to the configured npm registry and needs network access. This authorized check explicitly used `registry.npmjs.org`. The final authorized audit of the exact locked graph, including development and optional dependencies, was verified at `2026-10-06T12:52:07Z` and reported zero known findings at every severity. Its result covers named packages against the queried advisory database at that time and does not inventory the bundled affected parsers. For offline local installation, use `npm ci --no-audit --offline` with an already populated cache.

The 44 guard regression tests cover default/disabled watchers, valid options, invalid flags, accessor options, retained array semantics, old captured references, and asynchronous root/environment mutations using actual Vite config resolution. Five filesystem integration cases exercise a real self-accepting module's HMR hook and cached-transform invalidation in middleware mode without TCP/WebSocket clients, opt-in build output changes, and finite production builds. Benign public `watcher.add` controls positively observe glob alternatives without the policy and an actual literal filename/change with the policy; no crash or stack-exhaustion reproduction is claimed. The Rollup public watcher probe imports chokidar from its installed private bundled module, while the separate Vite watch-build case exercises the actual supported build API. These qualifications and final results appear in [validation](validation.md).

For demo compatibility checks, serve built `dist` assets with SPA fallback and open `/demo`, which enters the synthetic dashboard. Avoid importing the development proxy to `/api` on port 8443 into that preview. Check desktop/mobile navigation, custom palette and fonts, nested spacing, divider color, important zero padding, focus/forced colors and reduced motion in real supported browsers. Local static CSS checks complement these checks. Ubuntu ARM CI, Docker/musl and native Windows validation remain required for the final source revision.
