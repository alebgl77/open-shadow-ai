// @vitest-environment jsdom
import { useState } from 'react'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { AxiosError, AxiosHeaders } from 'axios'
import { createI18n, LanguageSelector, LOCALE_STORAGE_KEY, LocaleProvider, useI18n, type Locale } from '.'
import { dictionaries, type MessageKey } from './messages'
import App from '@/App'
import * as authApi from '@/api/auth'
import client from '@/api/client'
import { resetDemo } from '@/api/demo'
import { useAuthStore } from '@/stores/auth'
import Login from '@/pages/Login'
import Network from '@/pages/Network'
import Settings from '@/pages/Settings'
import ErrorAlert from '@/components/ui/ErrorAlert'
import ErrorBoundary from '@/components/ui/ErrorBoundary'

const clients: QueryClient[] = []
const locales: Locale[] = ['en', 'fr', 'zh-CN']
function securitySnapshot() {
  const { session, mode, csrfToken, isAuthenticated, restoring, user } = useAuthStore.getState()
  return { session, mode, csrfToken, isAuthenticated, restoring, user: user ? { ...user } : null }
}
function mount(element: React.ReactNode, path = '/') {
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  clients.push(queries)
  return { queries, ...render(<LocaleProvider><QueryClientProvider client={queries}><MemoryRouter initialEntries={[path]}>{element}</MemoryRouter></QueryClientProvider></LocaleProvider>) }
}
function Probe() {
  const { tr, formatNumber, formatDate } = useI18n()
  const [value, setValue] = useState(0)
  return <><LanguageSelector/><h1>{tr('Discoveries')}</h1><button onClick={() => setValue(value + 1)}>{value}</button><p>{formatNumber(12345.67)}</p><p>{formatDate('2026-10-08', { dateStyle: 'full' })}</p></>
}
beforeEach(() => {
  if (typeof globalThis.ResizeObserver === 'undefined') vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  localStorage.clear(); sessionStorage.clear(); useAuthStore.getState().logout(); resetDemo()
})
afterEach(() => { cleanup(); clients.splice(0).forEach(client => client.clear()); vi.restoreAllMocks(); vi.unstubAllGlobals(); useAuthStore.getState().logout() })

describe('locale dictionaries and formatting', () => {
  it('enforces exact message and placeholder parity for all supported languages', () => {
    const keys = Object.keys(dictionaries.en).sort() as MessageKey[]
    for (const locale of locales) {
      expect(Object.keys(dictionaries[locale]).sort()).toEqual(keys)
      for (const key of keys) {
        expect(dictionaries[locale][key].trim().length).toBeGreaterThan(0)
        expect((dictionaries[locale][key].match(/\{\w+\}/g) || []).sort()).toEqual((key.match(/\{\w+\}/g) || []).sort())
      }
    }
  })
  it.each(locales)('formats numbers, calendar days, relative time and invalid values in %s', locale => {
    const { formatDate, formatNumber, relativeTime, tr, textLabel } = createI18n(locale)
    const intlLocale = locale === 'en' ? 'en-US' : locale === 'fr' ? 'fr-FR' : locale
    expect(formatNumber(12345.67)).toBe(new Intl.NumberFormat(intlLocale).format(12345.67))
    expect(formatNumber(42.1, { style: 'currency', currency: 'USD' })).toBe(new Intl.NumberFormat(intlLocale, { style: 'currency', currency: 'USD' }).format(42.1))
    expect(formatDate('2026-10-08', { dateStyle: 'full' })).toBe(new Intl.DateTimeFormat(intlLocale, { timeZone: 'UTC', dateStyle: 'full' }).format(new Date('2026-10-08')))
    expect(relativeTime(0, 86400000)).toBe(new Intl.RelativeTimeFormat(intlLocale, { numeric: 'auto' }).format(-1, 'day'))
    expect(formatDate(0)).not.toBe(tr('Unknown'))
    expect(formatDate('invalid')).toBe(tr('Unknown'))
    expect(formatDate(null)).toBe(tr('Unknown'))
    expect(formatNumber(NaN)).toBe(tr('Unknown'))
    expect(relativeTime('invalid')).toBe(tr('Unknown'))
    expect(textLabel('__proto__')).toBe('__proto__')
    expect(textLabel('Upstream diagnostic: E42')).toBe('Upstream diagnostic: E42')
  })
  it('keeps independent pure lookups and escapes interpolated evidence in React', () => {
    const fr = createI18n('fr'); const zh = createI18n('zh-CN')
    expect(fr.tr('Discoveries')).toBe('Découvertes')
    expect(zh.tr('Discoveries')).toBe('发现')
    expect(fr.tr('Discoveries')).toBe('Découvertes')
    render(<p>{fr.tr('Review {name}', { name: '<img src=x onerror=alert(1)>' })}</p>)
    expect(document.querySelector('img')).toBeNull()
    expect(screen.getByText(/<img src=x/)).toBeTruthy()
  })
  it('retains the English fallback outside a provider', () => {
    render(<ErrorAlert/>)
    expect(screen.getByText('Failed to load data')).toBeTruthy()
  })
  it.each(locales)('translates bounded pipeline enums while preserving unknown technical identifiers in %s', locale => {
    const { enumLabel, tr } = createI18n(locale)
    if (locale !== 'en') for (const [value, key] of [['ingest', 'Ingestion'], ['correlation', 'Correlation'], ['blocked', 'Blocked'], ['processing', 'Processing'], ['stale', 'Stale']] as Array<[string, MessageKey]>) expect(enumLabel(value)).toBe(tr(key))
    expect(enumLabel('future_pipeline_stage')).toBe('future_pipeline_stage')
    expect(enumLabel('vendor_custom_state')).toBe('vendor_custom_state')
    expect(enumLabel('Language')).toBe('Language')
    expect(enumLabel('__proto__')).toBe('__proto__')
  })
})

describe('language selection and persistence', () => {
  it('switches English, French and Chinese without remounting state or changing auth', () => {
    useAuthStore.getState().login('csrf-private', { user_id: '1', username: 'reader', email: null, role: 'viewer', is_active: true })
    const auth = useAuthStore.getState()
    localStorage.setItem('other-application-key', 'keep')
    mount(<Probe/>)
    fireEvent.click(screen.getByRole('button', { name: '0' }))
    for (const locale of ['fr', 'zh-CN', 'en'] as const) {
      fireEvent.change(screen.getByRole('combobox'), { target: { value: locale } })
      expect(screen.getByRole('heading').textContent).toBe(createI18n(locale).tr('Discoveries'))
      expect(screen.getByRole('combobox').getAttribute('aria-label')).toBe(createI18n(locale).tr('Language'))
      expect(screen.getByRole('button', { name: '1' })).toBeTruthy()
      expect(document.documentElement.lang).toBe(locale)
      expect(document.title).toBe(createI18n(locale).tr('Open Shadow AI — Evidence & Governance'))
      expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe(locale)
      expect(useAuthStore.getState()).toBe(auth)
    }
    expect(localStorage.getItem('other-application-key')).toBe('keep')
    expect(Object.values(localStorage)).not.toContain('csrf-private')
  })
  it.each(['fr', 'zh-CN'] as const)('restores a valid persisted locale %s', locale => {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale)
    mount(<Probe/>)
    expect(screen.getByRole('heading').textContent).toBe(createI18n(locale).tr('Discoveries'))
    expect(document.documentElement.lang).toBe(locale)
  })
  it.each(['de', 'FR', '"fr"', '<script>', 'null', ''])('rejects malformed stored locale %s', value => {
    localStorage.setItem(LOCALE_STORAGE_KEY, value)
    mount(<Probe/>)
    expect(screen.getByRole('heading').textContent).toBe('Discoveries')
    expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('en')
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'unsupported' } })
    expect(document.documentElement.lang).toBe('en')
  })
  it('allows selection when storage reads and writes throw', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('Blocked storage') })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Blocked storage') })
    mount(<Probe/>)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'fr' } })
    expect(screen.getByRole('heading').textContent).toBe('Découvertes')
    expect(document.documentElement.lang).toBe('fr')
  })
})

describe('localized live UI states', () => {
  it('switches existing login inputs and pending/auth errors while retaining entered credentials', async () => {
    let resolveProviders!: (value: { data: { local_enabled: boolean; sso: null } }) => void
    vi.spyOn(client, 'get').mockReturnValue(new Promise(resolve => { resolveProviders = resolve }))
    const post = vi.spyOn(client, 'post').mockRejectedValue(new AxiosError('Forbidden', '401', undefined, undefined, { status: 401, statusText: 'Unauthorized', data: {}, headers: {}, config: { headers: new AxiosHeaders() } }))
    mount(<Login/>, '/login')
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'private-user' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'private-password' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Language' }), { target: { value: 'fr' } })
    expect(screen.getByRole('status').textContent).toBe('Vérification des options de connexion…')
    expect((screen.getByLabelText('Nom d’utilisateur') as HTMLInputElement).value).toBe('private-user')
    await act(async () => resolveProviders({ data: { local_enabled: true, sso: null } }))
    fireEvent.click(screen.getByRole('button', { name: 'Se connecter à l’espace de travail' }))
    expect((await screen.findByRole('alert')).textContent).toBe('Le nom d’utilisateur ou le mot de passe est incorrect.')
    expect(post).toHaveBeenCalledWith('/auth/login', { username: 'private-user', password: 'private-password' }, { headers: { 'X-Session-Mode': 'cookie' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Langue' }), { target: { value: 'zh-CN' } })
    expect(screen.getByRole('alert').textContent).toBe('用户名或密码错误。')
    expect((screen.getByLabelText('密码') as HTMLInputElement).value).toBe('private-password')
    expect(Object.values(localStorage)).not.toContain('private-password')
  })
  it.each(['fr', 'zh-CN'] as const)('preserves viewer authorization and localizes denied UI in %s', locale => {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale)
    useAuthStore.getState().login('viewer-csrf', { user_id: 'viewer', username: 'reader', email: null, role: 'viewer', is_active: true })
    const get = vi.spyOn(client, 'get')
    const view = mount(<Network/>, '/network')
    expect(screen.getByRole('alert').textContent).toContain(createI18n(locale).tr('Network access requires an analyst or administrator role.'))
    expect(get).not.toHaveBeenCalled()
    view.unmount()
    mount(<Settings/>, '/settings')
    expect(screen.getByText(createI18n(locale).tr('Workspace administration requires an administrator role.'))).toBeTruthy()
    expect(get).not.toHaveBeenCalled()
  })
  it('localizes the error boundary and preserves an unknown diagnostic as evidence', () => {
    localStorage.setItem(LOCALE_STORAGE_KEY, 'zh-CN')
    const QuietConsole = vi.spyOn(console, 'error').mockImplementation(() => {})
    function Broken(): never { throw new Error('Upstream diagnostic: E42') }
    mount(<ErrorBoundary><Broken/></ErrorBoundary>)
    expect(screen.getByRole('heading').textContent).toBe('发生错误')
    expect(screen.getByText('Upstream diagnostic: E42')).toBeTruthy()
    expect(screen.getByRole('button', { name: '重新加载页面' })).toBeTruthy()
    QuietConsole.mockRestore()
  })
})

describe.each(locales)('%s full console', locale => {
  it.each([
    ['/dashboard', 'Evidence into oversight.'], ['/discoveries', 'Discoveries'], ['/users', 'Identity signals'],
    ['/oauth-apps', 'OAuth AI Apps'], ['/extensions', 'AI Browser Extensions'], ['/local-ai', 'Local AI Runtimes'],
    ['/network', 'Network observations'], ['/governance', 'Governance Policies'], ['/catalog', 'AI catalog'],
    ['/sources', 'Sources & coverage'], ['/settings', 'Settings'],
  ] as Array<[string, MessageKey]>)('renders localized page and navigation at %s', async (path, heading) => {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale)
    useAuthStore.getState().enterDemo()
    const auth = securitySnapshot()
    const restore = vi.spyOn(authApi, 'restoreSession')
    mount(<App/>, path)
    expect(await screen.findByRole('heading', { level: 1, name: createI18n(locale).tr(heading) })).toBeTruthy()
    expect(screen.getByRole('combobox', { name: createI18n(locale).tr('Language') })).toBeTruthy()
    const nav = screen.getByRole('navigation', { name: createI18n(locale).tr('Main navigation') })
    expect(within(nav).getByRole('link', { name: createI18n(locale).tr('Sources') }).getAttribute('href')).toBe('/sources')
    await waitFor(() => {
      expect(securitySnapshot()).toStrictEqual(auth)
      expect(restore).toHaveBeenCalledExactlyOnceWith()
    })
    let displayedLocale = locale
    for (const nextLocale of locales) {
      fireEvent.change(screen.getByRole('combobox', { name: createI18n(displayedLocale).tr('Language') }), { target: { value: nextLocale } })
      displayedLocale = nextLocale
      expect(screen.getByRole('heading', { level: 1, name: createI18n(nextLocale).tr(heading) })).toBeTruthy()
      const updatedNav = screen.getByRole('navigation', { name: createI18n(nextLocale).tr('Main navigation') })
      expect(within(updatedNav).getByRole('link', { name: createI18n(nextLocale).tr('Sources') }).getAttribute('href')).toBe('/sources')
      expect(securitySnapshot()).toStrictEqual(auth)
      expect(restore).toHaveBeenCalledExactlyOnceWith()
    }
  })
})
