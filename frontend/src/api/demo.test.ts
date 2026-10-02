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
describe('CSV evidence export', ()=>{
  it('escapes formula payloads, quotes, separators and multiline strings',()=>{
    expect(csvCell('=HYPERLINK("bad")')).toBe('"\'=HYPERLINK(""bad"")"')
    expect(csvCell('a,b\nc')).toBe('"a,b\nc"')
    expect(csvCell(null)).toBe('""')
  })
})
