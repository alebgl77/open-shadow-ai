import { create } from 'zustand'

export interface User {
  user_id: string
  username: string
  email: string | null
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
}
interface AuthState {
  token: string | null
  user: User | null
  isAuthenticated: boolean
  mode: 'live' | 'demo'
  session: number
  login: (token: string, user: User) => void
  enterDemo: () => void
  logout: () => void
}
// Credentials intentionally live only in memory. Reloading ends the session.
try { localStorage.removeItem('shadai-auth') } catch { /* Storage may be disabled. */ }
export const useAuthStore = create<AuthState>((set) => ({
  token: null, user: null, isAuthenticated: false, mode: 'live', session: 0,
  login: (token, user) => set(s => ({ token, user, isAuthenticated: true, mode: 'live', session: s.session + 1 })),
  enterDemo: () => set(s => ({ token: null, user: { user_id: 'demo-reviewer', username: 'Demo reviewer', email: null, role: 'admin', is_active: true }, isAuthenticated: true, mode: 'demo', session: s.session + 1 })),
  logout: () => set(s => ({ token: null, user: null, isAuthenticated: false, mode: 'live', session: s.session + 1 })),
}))
