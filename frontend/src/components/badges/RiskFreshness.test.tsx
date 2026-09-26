import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import RiskBadge from './RiskBadge'
import ApprovalBadge from './ApprovalBadge'

describe('governance and risk freshness', () => {
  it('replaces a stale score and severity with an explicit recalculation state', () => {
    const html = renderToStaticMarkup(<RiskBadge level="critical" score={89} showScore stale />)
    expect(html).toContain('Needs recalculation')
    expect(html).not.toContain('(89)')
    expect(html).not.toContain('critical')
  })
  it('preserves existing badges when older APIs omit freshness fields', () => {
    expect(renderToStaticMarkup(<RiskBadge level="high" score={78} showScore />)).toContain('(78)')
    expect(renderToStaticMarkup(<RiskBadge level="high" score={78} showScore stale={false} />)).not.toContain('Needs recalculation')
  })
  it('labels expired approval without inferring status from absent fields', () => {
    expect(renderToStaticMarkup(<ApprovalBadge status="expired" />)).toContain('Approval expired')
    expect(renderToStaticMarkup(<ApprovalBadge status="active" />)).toBe('')
    expect(renderToStaticMarkup(<ApprovalBadge status="none" />)).toBe('')
    expect(renderToStaticMarkup(<ApprovalBadge />)).toBe('')
  })
})
