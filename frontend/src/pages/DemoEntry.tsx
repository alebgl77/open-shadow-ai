import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
export default function DemoEntry() {
  const [ready, setReady] = useState(false)
  useEffect(()=>{
    let active = true
    import('@/api/demo').then(({resetDemo})=>{ if (active) { resetDemo(); useAuthStore.getState().enterDemo(); setReady(true) } })
    return ()=>{ active = false }
  },[])
  return ready ? <Navigate to="/dashboard" replace/> : <p className="p-8 text-slate-400" role="status">Opening the synthetic demo workspace…</p>
}
