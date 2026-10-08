// @vitest-environment jsdom
import { cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { LOCALE_STORAGE_KEY, LocaleProvider, type Locale } from '@/i18n'
import EntityTypeBadge from './EntityTypeBadge'
import StatusBadge from './StatusBadge'
import ClassificationBadge from './ClassificationBadge'

const locales: Locale[] = ['en', 'fr', 'zh-CN']
const entityCases = [
  ['saas_app', 'globe', ['SaaS', 'SaaS', 'SaaS']],
  ['api_service', 'code', ['API', 'API', 'API']],
  ['browser_extension', 'puzzle', ['Extension', 'Extension', '扩展']],
  ['oauth_app', 'key', ['OAuth', 'OAuth', 'OAuth']],
  ['local_runtime', 'cpu', ['Local', 'Local', '本地']],
  ['local_container', 'container', ['Container', 'Conteneur', '容器']],
  ['desktop_app', 'monitor', ['Desktop', 'Bureau', '桌面']],
] as const
const statusCases = [
  ['new', 'bg-blue-500/15 text-blue-400', ['new', 'Nouveau', '新建']],
  ['investigating', 'bg-yellow-500/15 text-yellow-400', ['investigating', 'En cours d’analyse', '调查中']],
  ['classified', 'bg-emerald-500/15 text-emerald-400', ['classified', 'Classé', '已分类']],
  ['false_positive', 'bg-slate-500/15 text-slate-500 line-through', ['false positive', 'Faux positif', '误报']],
  ['escalated', 'bg-red-500/15 text-red-400', ['escalated', 'Transmis pour traitement', '已升级处理']],
] as const
const classificationCases = [
  ['sanctioned', 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30', ['sanctioned', 'Autorisé', '已批准']],
  ['tolerated', 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30', ['tolerated', 'Toléré', '已容许']],
  ['unsanctioned', 'bg-red-500/15 text-red-400 border border-red-500/30', ['unsanctioned', 'Non autorisé', '未批准']],
  ['unknown', 'bg-slate-500/15 text-slate-400 border border-slate-500/30', ['unknown', 'Inconnu', '未知']],
] as const

beforeEach(() => localStorage.clear())
afterEach(() => cleanup())

describe.each(locales)('%s mounted badges', locale => {
  const localeIndex = locales.indexOf(locale)
  function mount(children: React.ReactNode) {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale)
    return render(<LocaleProvider>{children}</LocaleProvider>).container
  }

  it.each(['vendor_custom_entity', 'Vendor_Custom_State', 'Vendor_Custom_Class', 'Vendor_Custom.Value:β!?', 'active', 'Language'])('preserves unknown %s in all three wrappers', value => {
    const container = mount(<><EntityTypeBadge entityType={value}/><StatusBadge status={value}/><ClassificationBadge classification={value}/></>)
    const [entity, status, classification] = Array.from(container.children)
    expect([entity.textContent, status.textContent, classification.textContent]).toEqual([value, value, value])
    expect(entity.querySelector('svg.lucide-globe')).toBeTruthy()
    expect(status.className).toContain('bg-blue-500/15 text-blue-400')
    expect(status.querySelector('span')).toBeNull()
    expect(classification.className).toContain('bg-slate-500/15 text-slate-400 border border-slate-500/30')
  })

  it.each(['__proto__', 'constructor', 'toString'])('renders inherited key %s safely and literally', value => {
    const container = mount(<><EntityTypeBadge entityType={value}/><StatusBadge status={value}/><ClassificationBadge classification={value}/></>)
    const [entity, status, classification] = Array.from(container.children)
    expect([entity.textContent, status.textContent, classification.textContent]).toEqual([value, value, value])
    expect(entity.querySelector('svg.lucide-globe')).toBeTruthy()
    expect(status.className).toContain('bg-blue-500/15 text-blue-400')
    expect(classification.className).toContain('bg-slate-500/15 text-slate-400 border border-slate-500/30')
  })

  it('retains canonical entity labels and icons', () => {
    const container = mount(<>{entityCases.map(([value]) => <EntityTypeBadge key={value} entityType={value}/>)}</>)
    entityCases.forEach(([, icon, labels], index) => {
      expect(container.children[index].textContent).toBe(labels[localeIndex])
      expect(container.children[index].querySelector(`svg.lucide-${icon}`)).toBeTruthy()
      expect(container.children[index].className).toContain('bg-surface-700 text-slate-300')
    })
  })

  it('retains status canonical and uppercase aliases with their styles', () => {
    const container = mount(<>{statusCases.flatMap(([value]) => [value, value.toUpperCase()].map(alias => <StatusBadge key={alias} status={alias}/>))}</>)
    statusCases.forEach(([value, style, labels], index) => {
      for (const badge of [container.children[index * 2], container.children[index * 2 + 1]]) {
        expect(badge.textContent).toBe(labels[localeIndex])
        expect(badge.className).toContain(style)
        expect(Boolean(badge.querySelector('span.bg-blue-400'))).toBe(value === 'new')
      }
    })
  })

  it('retains classification canonical and uppercase aliases with their styles', () => {
    const container = mount(<>{classificationCases.flatMap(([value]) => [value, value.toUpperCase()].map(alias => <ClassificationBadge key={alias} classification={alias}/>))}</>)
    classificationCases.forEach(([, style, labels], index) => {
      for (const badge of [container.children[index * 2], container.children[index * 2 + 1]]) {
        expect(badge.textContent).toBe(labels[localeIndex])
        expect(badge.className).toContain(style)
      }
    })
  })

  it('keeps unsupported entity aliases literal and respects hidden labels', () => {
    const container = mount(<><EntityTypeBadge entityType="LOCAL_CONTAINER"/><EntityTypeBadge entityType="local_container" showLabel={false}/><EntityTypeBadge entityType="__proto__" showLabel={false}/></>)
    expect(container.children[0].textContent).toBe('LOCAL_CONTAINER')
    expect(container.children[0].querySelector('svg.lucide-globe')).toBeTruthy()
    expect(container.children[1].textContent).toBe('')
    expect(container.children[1].querySelector('svg.lucide-container')).toBeTruthy()
    expect(container.children[2].textContent).toBe('')
    expect(container.children[2].querySelector('svg.lucide-globe')).toBeTruthy()
  })
})
