import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { dictionaries, type MessageKey } from './messages'

export type Locale = keyof typeof dictionaries
export const LOCALE_STORAGE_KEY = 'open-shadow-ai.locale'
export const isLocale = (value: unknown): value is Locale => value === 'en' || value === 'fr' || value === 'zh-CN'
const intlLocales: Record<Locale, string> = { en: 'en-US', fr: 'fr-FR', 'zh-CN': 'zh-CN' }
type Parameters = Record<string, string | number>

// Only known UI labels are translated. Unknown source evidence is preserved verbatim.
export function createI18n(locale: Locale) {
  const dictionary = dictionaries[locale]
  const tr = (key: MessageKey, parameters: Parameters = {}): string => dictionary[key].replace(/\{(\w+)\}/g, (token, name: string) => Object.hasOwn(parameters, name) ? String(parameters[name]) : token)
  const textLabel = (value: string) => Object.hasOwn(dictionary, value) ? tr(value as MessageKey) : value
  const formatNumber = (value: number, options?: Intl.NumberFormatOptions) => Number.isFinite(value) ? new Intl.NumberFormat(intlLocales[locale], options).format(value) : tr('Unknown')
  const formatDate = (value: string | number | Date | null | undefined, options: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' }) => {
    const date = value instanceof Date ? value : value == null || value === '' ? new Date(NaN) : new Date(value)
    const dateOptions = typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) ? { timeZone: 'UTC', ...options } : options
    return Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat(intlLocales[locale], dateOptions).format(date) : tr('Unknown')
  }
  const relativeTime = (value: string | number | Date, now = Date.now()) => {
    const date = value instanceof Date ? value : new Date(value)
    const seconds = (date.getTime() - now) / 1000
    if (!Number.isFinite(seconds)) return tr('Unknown')
    const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]]
    const [unit, divisor] = units.find(([, size]) => Math.abs(seconds) >= size) || units[units.length - 1]
    return new Intl.RelativeTimeFormat(intlLocales[locale], { numeric: 'auto' }).format(Math.round(seconds / divisor), unit)
  }
  const enumLabel = (value: string) => {
    const known: Record<string, MessageKey> = {
      new: 'New', investigating: 'Investigating', classified: 'Classified', false_positive: 'False Positive', escalated: 'Escalated',
      sanctioned: 'Sanctioned', unsanctioned: 'Unsanctioned', tolerated: 'Tolerated', unknown: 'Unknown',
      active: 'Active', inactive: 'Inactive', warning: 'Warning', revoked: 'Revoked', quiet: 'Quiet', stale: 'Stale', healthy: 'Healthy', degraded: 'Degraded', unavailable: 'Unavailable',
      critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Information', very_high: 'Very high',
      admin: 'Administrator', analyst: 'Analyst', viewer: 'Viewer',
      saas_app: 'SaaS application', api_service: 'API service', browser_extension: 'Browser extension', oauth_app: 'OAuth application', local_runtime: 'Local runtime', local_container: 'Local container', desktop_app: 'Desktop application',
      network: 'Passive network', dns: 'DNS', proxy: 'Proxy', endpoint: 'Endpoint', browser: 'Browser', oauth: 'OAuth', directory: 'Directory', instrumented: 'Instrumented', casb: 'CASB',
      observe: 'Observe', monitor: 'Monitor', alert: 'Alert', block: 'Block', enforce: 'Enforce',
      llm: 'Large language model', coding: 'Coding', assistant: 'Assistant', image: 'Image generation', audio: 'Audio', video: 'Video', search: 'Search', productivity: 'Productivity', other: 'Other',
      llm_chat: 'Chat with language models', code_assistant: 'Code assistant', ai_platform: 'AI platform', browser_extension_ai: 'AI browser extension', image_gen: 'Image generation', voice_ai: 'Voice AI', video_ai: 'Video AI', data_ai: 'Data AI', translation_ai: 'Translation AI', writing_assistant: 'Writing assistant', search_ai: 'Search AI', design_ai: 'Design AI', productivity_ai: 'Productivity', agent_automation: 'AI automation',
      normalizer: 'Normalizer', correlator: 'Correlator', recent: 'Recent', running: 'Running', idle: 'Idle', failed: 'Failed', available: 'Available', first_party: 'First-party', community: 'Community', builtin: 'Built-in',
      reported: 'Reported', ingest: 'Ingestion', correlation: 'Correlation', blocked: 'Blocked', processing: 'Processing',
    }
    if (!Object.hasOwn(known, value)) return value
    if (locale === 'en') return value === 'network' ? tr('Passive network') : value.replaceAll('_', ' ')
    return tr(known[value])
  }
  return { locale, tr, textLabel, enumLabel, formatDate, formatNumber, relativeTime }
}

const defaultContext = { ...createI18n('en'), setLocale: (_locale: Locale) => {} }
export const LocaleContext = createContext(defaultContext)
export const useI18n = () => useContext(LocaleContext)

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, updateLocale] = useState<Locale>(() => {
    try {
      const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY)
      return isLocale(stored) ? stored : 'en'
    } catch { return 'en' }
  })
  const setLocale = useCallback((next: Locale) => { if (isLocale(next)) updateLocale(next) }, [])
  useEffect(() => {
    document.documentElement.lang = locale
    const { tr } = createI18n(locale)
    document.title = tr('Open Shadow AI — Evidence & Governance')
    document.querySelector('meta[name="description"]')?.setAttribute('content', tr('Open Shadow AI is an open source evidence and governance console. Discover observed AI activity, review source coverage, and record decisions.'))
    try { window.localStorage.setItem(LOCALE_STORAGE_KEY, locale) } catch { /* Locale selection remains available when browser storage is blocked. */ }
  }, [locale])
  const value = useMemo(() => ({ ...createI18n(locale), setLocale }), [locale, setLocale])
  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>
}

export function LanguageSelector() {
  const { locale, setLocale, tr } = useI18n()
  return <label className="inline-flex items-center gap-2 text-xs text-slate-400"><span className="sr-only">{tr('Language')}</span><select aria-label={tr('Language')} value={locale} onChange={event => { if (isLocale(event.target.value)) setLocale(event.target.value) }} className="field text-xs max-w-32"><option value="en" lang="en">English</option><option value="fr" lang="fr">Français</option><option value="zh-CN" lang="zh-CN">简体中文</option></select></label>
}
