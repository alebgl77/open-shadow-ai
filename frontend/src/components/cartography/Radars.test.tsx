// @vitest-environment jsdom
import { useState } from 'react'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { LocaleContext, createI18n, type Locale } from '@/i18n'
import type { CatalogItem } from '@/types'
import type { NetworkRelation, NetworkRelations } from '@/api/network'
import Radars from './Radars'
import { buildRadars, type RadarSelection } from './radar'

const first = { source_ip: '192.0.2.1', domain: '__proto__', catalog_match_id: 'raw-id', protocol: 'QUIC', observations: 2, first_seen: '', last_seen: '' } as NetworkRelation
const network = (items = [first]): NetworkRelations => ({ items, hours: 24, protocol: null, total_relations: 900, represented_relations: items.length, total_observations: 901, represented_observations: 777, truncated: true, limitations: [] })
const catalog = [{ catalog_item_id: 'raw-id', canonical_name: 'Untouched raw name', category: 'constructor' }] as CatalogItem[]
function Fixture({ locale = 'en', data = network(), labels = catalog, loading = false }: { locale?: Locale; data?: NetworkRelations; labels?: CatalogItem[]; loading?: boolean }) {
  const [selected, select] = useState<RadarSelection | null>(null)
  return <LocaleContext.Provider value={{ ...createI18n(locale), setLocale: () => {} }}><Radars {...buildRadars(data, loading ? undefined : labels)} network={data} catalog={labels} catalogCapped networkLoading={false} catalogLoading={loading} selected={selected} onSelect={select} onClose={() => select(null)} onInspect={() => {}}/></LocaleContext.Provider>
}
afterEach(cleanup)
describe('accessible loaded observation radars', () => {
  it.each(['en', 'fr', 'zh-CN'] as const)('renders localized fixed scale, numeric axis controls, denominator, raw evidence and subset limits in %s', locale => {
    const i18n = createI18n(locale), { container } = render(<Fixture locale={locale}/>)
    const protocols = screen.getByRole('region', { name: i18n.tr('Protocol distribution') })
    const families = screen.getByRole('region', { name: i18n.tr('Current catalog families') })
    expect(within(protocols).getAllByRole('button')).toHaveLength(4)
    expect(within(families).getAllByRole('button')).toHaveLength(6)
    expect(within(protocols).getByRole('img').getAttribute('aria-labelledby')).toBeTruthy()
    expect(container.querySelectorAll('.cart-radar-scale')).toHaveLength(10)
    expect(within(protocols).getByText(i18n.tr('Loaded denominator: {count} observations.', { count: i18n.formatNumber(2) }))).toBeTruthy()
    expect(screen.getByText(i18n.tr('Computed loaded observations: {represented}; full selected-window observations: {total}.', { represented: i18n.formatNumber(2), total: i18n.formatNumber(901) }))).toBeTruthy()
    expect(screen.getByText(i18n.tr('Catalog labels cover at most 500 entries. Unloaded service IDs are shown verbatim.'))).toBeTruthy()
    const quic = within(protocols).getByRole('button', { name: /QUIC/ })
    quic.focus(); expect(document.activeElement).toBe(quic)
    fireEvent.click(quic)
    const drilldown = screen.getByRole('region', { name: i18n.tr('Radar relationship drilldown') })
    expect(within(drilldown).getByText('constructor')).toBeTruthy()
    expect(within(drilldown).getByText('raw-id')).toBeTruthy()
    expect(within(drilldown).getByText(/__proto__/)).toBeTruthy()
    expect(within(protocols).getByRole('button', { name: /QUIC/ }).getAttribute('aria-pressed')).toBe('true')
    fireEvent.click(within(drilldown).getByRole('button', { name: i18n.tr('Close radar drilldown') }))
    expect(screen.queryByRole('region', { name: i18n.tr('Radar relationship drilldown') })).toBeNull()
  })
  it('makes real zero axes selectable and displays an explicit empty group without changing values', () => {
    render(<Fixture/>)
    const protocols = screen.getByRole('region', { name: 'Protocol distribution' })
    fireEvent.click(within(protocols).getByRole('button', { name: /DNS/ }))
    expect(screen.getByText('No loaded relationships belong to this axis. This does not establish an absence of activity.')).toBeTruthy()
    expect(within(protocols).getAllByText('0%')).toHaveLength(4)
    expect(screen.getAllByTestId('radar-values')).toHaveLength(2)
  })
  it('does not draw a data polygon or fabricate percentages when all counts are zero', () => {
    render(<Fixture data={network([{ ...first, observations: 0 }])}/>)
    expect(screen.queryByTestId('radar-values')).toBeNull()
    expect(screen.getAllByText('No loaded observations. Percentages are undefined when the denominator is zero.')).toHaveLength(2)
    expect(within(screen.getByRole('region', { name: 'Protocol distribution' })).getByRole('button', { name: /QUIC/ }).textContent).toContain('—')
  })
  it('shows unavailable family data while the catalog loads without disabling protocol evidence', () => {
    render(<Fixture loading/>)
    const families = screen.getByRole('region', { name: 'Current catalog families' })
    expect(within(families).getByRole('status').textContent).toContain('Loading radar evidence')
    expect(within(families).getAllByRole('button').every(button => (button as HTMLButtonElement).disabled)).toBe(true)
    expect(screen.getAllByTestId('radar-values')).toHaveLength(1)
    expect((within(screen.getByRole('region', { name: 'Protocol distribution' })).getByRole('button', { name: /QUIC/ }) as HTMLButtonElement).disabled).toBe(false)
  })
  it('shows sanitized unavailable charts for invalid data rather than a zero polygon', () => {
    render(<Fixture data={network([{ ...first, observations: NaN }])}/>)
    expect(screen.queryByTestId('radar-values')).toBeNull()
    expect(screen.getAllByText(/observation counts are invalid/)).toHaveLength(2)
    expect(screen.queryByText(/Computed loaded observations/)).toBeNull()
  })
  it.each([-1, NaN, Infinity, 1])('keeps a valid loaded distribution but never claims coverage from an incoherent full-window total: %s', total_observations => {
    render(<Fixture data={{ ...network(), total_observations }}/>)
    expect(screen.getAllByTestId('radar-values')).toHaveLength(2)
    expect(screen.getAllByText('Loaded denominator: 2 observations.')).toHaveLength(2)
    expect(screen.queryByText(/Computed loaded observations/)).toBeNull()
    expect(screen.getByText(/Percentages describe this subset, not the full window or AI use/)).toBeTruthy()
  })
})
