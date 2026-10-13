import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AxiosError, AxiosHeaders } from 'axios'
import { demoRequest, resetDemo } from './demo'
import { useAuthStore } from '@/stores/auth'
import client from './client'
import { listDetections } from './detections'
import { csvCell } from '@/lib/export'

describe('explicit synthetic workspace', ()=>{
  beforeEach(()=>{ resetDemo(); useAuthStore.getState().logout() })
  it('provides internally consistent event aggregates and unknown cost', ()=>{
    const evidence = demoRequest('get','/dashboard/evidence') as {total_events:number; by_source:Array<{events:number}>; measurement:{cost_usd:number|null}}
    expect(evidence.by_source.reduce((sum,source)=>sum+source.events,0)).toBe(evidence.total_events)
    expect(evidence.measurement.cost_usd).toBeNull()
  })
  it('applies search, multi-risk filters, ordering, pagination and total independently', ()=>{
    const result = demoRequest('get','/detections?risk_level=high,critical&sort_by=risk_score&sort_order=desc&page_size=10') as {total:number; items:Array<{entity_name:string}>}
    expect(result.total).toBe(2); expect(result.items[0].entity_name).toBe('Otter.ai')
    expect((demoRequest('get','/detections?search=claude') as {total:number}).total).toBe(1)
    expect((demoRequest('get','/detections?page=2&page_size=10') as {items:unknown[]}).items).toHaveLength(0)
  })
  it('updates reviews, aggregate counts and audit without persistence; resets cleanly', ()=>{
    demoRequest('patch','/detections/demo-1',{analyst_status:'investigating',classification:'sanctioned',analyst_notes:'Review context'})
    expect(demoRequest('get','/dashboard/summary')).toMatchObject({unreviewed:3,unsanctioned:1})
    expect(demoRequest('get','/audit/logs')).toHaveLength(1)
    resetDemo()
    expect(demoRequest('get','/dashboard/summary')).toMatchObject({unreviewed:4,unsanctioned:2})
    expect(demoRequest('get','/audit/logs')).toHaveLength(0)
  })
  it('rejects unknown routes instead of inventing success', ()=>{
    expect(()=>demoRequest('post','/not-supported')).toThrow('Demo route unavailable')
    expect(()=>demoRequest('get','/detections/not-found')).toThrow('not found')
  })
  it('accepts exactly the sort columns the API supports', ()=>{
    const result = demoRequest('get','/detections?sort_by=impacted_users_count&sort_order=desc&page_size=100') as {items:Array<{impacted_users_count:number}>}
    const counts = result.items.map(item=>item.impacted_users_count)
    expect(counts).toEqual([...counts].sort((a,b)=>b-a))
    expect(()=>demoRequest('get','/detections?sort_by=evidence_bundle')).toThrow('Invalid sort')
  })
  it('enters demo without a live CSRF token and forgets it at sign-out', ()=>{
    useAuthStore.getState().login('csrf-secret', {user_id:'1',username:'analyst',email:null,role:'analyst',is_active:true})
    useAuthStore.getState().enterDemo()
    expect(useAuthStore.getState()).toMatchObject({csrfToken:null, mode:'demo',isAuthenticated:true})
    useAuthStore.getState().logout()
    expect(useAuthStore.getState()).toMatchObject({csrfToken:null,user:null,isAuthenticated:false,mode:'live'})
  })
  it('never falls back to fixtures when a live request fails', async()=>{
    const failure = vi.fn(async()=>{ throw new AxiosError('Offline','ERR_NETWORK') })
    await expect(client.get('/dashboard/summary',{adapter:failure})).rejects.toThrow('Offline')
    expect(failure).toHaveBeenCalledOnce()
    expect(useAuthStore.getState().mode).toBe('live')
  })
  it('does not expire a new session because of an older request response', async()=>{
    const user = {user_id:'1',username:'analyst',email:null,role:'analyst' as const,is_active:true}
    useAuthStore.getState().login('old-csrf',user)
    await expect(client.get('/dashboard/summary',{adapter:async config=>{
      useAuthStore.getState().login('new-csrf',user)
      throw new AxiosError('Unauthorized','401',config,null,{data:{},status:401,statusText:'Unauthorized',headers:new AxiosHeaders(),config})
    }})).rejects.toThrow('Unauthorized')
    expect(useAuthStore.getState()).toMatchObject({csrfToken:'new-csrf',isAuthenticated:true})
  })
  it('expires the matching live session on unauthorized response', async()=>{
    useAuthStore.getState().login('expired',{user_id:'1',username:'analyst',email:null,role:'analyst',is_active:true})
    await expect(client.get('/dashboard/summary',{adapter:async config=>{
      throw new AxiosError('Unauthorized','401',config,null,{data:{},status:401,statusText:'Unauthorized',headers:new AxiosHeaders(),config})
    }})).rejects.toThrow('Unauthorized')
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
  })
  it('normalizes untrusted page limits before issuing API requests', async()=>{
    const spy=vi.spyOn(client,'get').mockResolvedValueOnce({data:{items:[],total:0,page:1,page_size:100}})
    await listDetections({page:-3,page_size:1000})
    expect(spy).toHaveBeenCalledWith('/detections?page=1&page_size=100')
    spy.mockRestore()
  })
})
describe('synthetic extension inventory', ()=>{
  beforeEach(()=>{ resetDemo() })
  const inventory = () => demoRequest('get','/extensions/inventory?page_size=100') as {items:Array<{inventory_key:string; browser:string; install_source:string; enabled:boolean|null; catalog_item_id:string|null; host_label:string}>; total:number; identity_window:{days:number}; identity_mode:string}
  it('keeps the summary, the rows and the change history internally consistent', ()=>{
    const rows = inventory()
    const summary = demoRequest('get','/extensions/inventory/summary') as {installations:number; hosts:number; extensions:number; catalog_matched:number; by_browser:Record<string,number>; by_install_source:Record<string,number>; by_enabled:Record<string,number>; version_changes_7d:number; identity_mode:string; limitations:string[]}
    expect(rows.total).toBe(24); expect(rows.items).toHaveLength(24); expect(rows.identity_window.days).toBe(30); expect(rows.identity_mode).toBe('pseudonymized')
    expect(summary.installations).toBe(24); expect(summary.hosts).toBe(3); expect(summary.extensions).toBe(6); expect(summary.catalog_matched).toBe(4)
    for (const counts of [summary.by_browser, summary.by_install_source, summary.by_enabled]) expect(Object.values(counts).reduce((sum,value)=>sum+value,0)).toBe(24)
    expect(Object.keys(summary.by_install_source)).toEqual(['', 'store','user','unpacked','external','policy','component','orphan','unknown'])
    expect(summary.by_install_source['']).toBe(2)
    expect(summary.limitations.some(limitation=>limitation.includes('fictional'))).toBe(true)
    const keys = new Set(rows.items.map(item=>item.inventory_key))
    const changes = demoRequest('get','/extensions/version-changes?page_size=100') as {items:Array<{inventory_key:string; observed_at:string; from_version:string|null; to_version:string|null}>; total:number; since:string; until:string}
    expect(changes.total).toBe(19)
    expect(changes.items.every(change=>keys.has(change.inventory_key) && change.to_version !== null)).toBe(true)
    expect(changes.items.map(change=>change.observed_at)).toEqual([...changes.items.map(change=>change.observed_at)].sort().reverse())
    expect(Date.parse(changes.until)-Date.parse(changes.since)).toBe(30*86400000)
    expect(summary.version_changes_7d).toBe(16)
    const history = demoRequest('get',`/extensions/inventory/${rows.items[0].inventory_key}/versions`) as {installation:{inventory_key:string}; changes:unknown[]}
    expect(history.installation.inventory_key).toBe(rows.items[0].inventory_key)
    expect(history.changes).toEqual(changes.items.filter(change=>change.inventory_key===rows.items[0].inventory_key))
    expect(()=>demoRequest('get',`/extensions/inventory/${'f'.repeat(64)}/versions`)).toThrow('not found')
  })
  it('applies the inventory filters, windows and sort order deterministically', ()=>{
    expect((demoRequest('get','/extensions/inventory?browser=chrome') as {total:number}).total).toBe(6)
    expect((demoRequest('get','/extensions/inventory?browser=chrome,edge&enabled=unknown') as {total:number}).total).toBe(4)
    expect((demoRequest('get','/extensions/inventory?install_source=store') as {total:number}).total).toBe(3)
    expect((demoRequest('get','/extensions/inventory?catalog_match=matched') as {total:number}).total).toBe(4)
    expect((demoRequest('get','/extensions/inventory?host=HOST-01') as {total:number}).total).toBe(8)
    expect((demoRequest('get','/extensions/inventory?search=SIDER') as {total:number}).total).toBe(4)
    expect((demoRequest('get','/extensions/inventory?host=host-02&search=sider') as {total:number}).total).toBe(0)
    expect((demoRequest('get','/extensions/inventory?extension_id=demo-extension-id&page=2&page_size=3') as {items:unknown[]; total:number; page:number}).items).toHaveLength(1)
    const versions = (demoRequest('get','/extensions/inventory?sort_by=version&sort_order=asc&page_size=100') as {items:Array<{version:string|null}>}).items.map(item=>item.version)
    expect(versions.slice(-5)).toEqual([null,null,null,null,null])
    expect(versions.slice(0,-5)).toEqual([...versions.slice(0,-5)].sort())
    expect([24,72,168].map(hours=>(demoRequest('get',`/extensions/version-changes?since=${new Date(Date.now()-hours*3600000).toISOString()}`) as {total:number}).total)).toEqual([3,7,16])
    expect((demoRequest('get','/extensions/version-changes?browser=safari&host=demo-host') as {total:number}).total).toBe(6)
  })
  it('rejects the filter values, sort columns and windows the API rejects', ()=>{
    expect(()=>demoRequest('get','/extensions/inventory?enabled=maybe')).toThrow('Invalid inventory filter')
    expect(()=>demoRequest('get','/extensions/inventory?catalog_match=all')).toThrow('Invalid inventory filter')
    expect(()=>demoRequest('get','/extensions/inventory?install_source=store,magic')).toThrow('Invalid install source')
    expect(()=>demoRequest('get','/extensions/inventory?sort_by=inventory_key')).toThrow('Invalid sort')
    expect(()=>demoRequest('get','/extensions/inventory?sort_order=sideways')).toThrow('Invalid sort')
    expect(()=>demoRequest('get','/extensions/version-changes?since=soon')).toThrow('Invalid version change window')
  })
  it('exports matching synthetic installations behind the warning and records the export', ()=>{
    const csv = demoRequest('post','/exports/extension-inventory?format=csv&browser=chrome&sort_by=browser&sort_order=asc') as string
    expect(csv.startsWith('# WARNING: Synthetic demo export.')).toBe(true)
    expect(csv.split('\r\n')).toHaveLength(7)
    const entry = (demoRequest('get','/audit/logs') as Array<{action:string; details:{count:number; filters:Record<string,string>}}>)[0]
    expect(entry.action).toBe('export_extension_inventory')
    expect(entry.details).toEqual({format:'csv', count:6, filters:{browser:'chrome'}})
    resetDemo()
    expect(demoRequest('get','/audit/logs')).toHaveLength(0)
  })
})
describe('CSV evidence export', ()=>{
  it('escapes formula payloads, quotes, separators and multiline strings',()=>{
    expect(csvCell('=HYPERLINK("bad")')).toBe('"\'=HYPERLINK(""bad"")"')
    expect(csvCell('a,b\nc')).toBe('"a,b\nc"')
    expect(csvCell(null)).toBe('""')
  })
})
