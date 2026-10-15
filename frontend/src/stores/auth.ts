import { create } from 'zustand'

export interface User {
  user_id: string
  username: string
  email: string | null
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
}
interface AuthState {
  csrfToken: string | null
  user: User | null
  isAuthenticated: boolean
  mode: 'live' | 'demo'
  session: number
  restoring: boolean
  cartographyDeniedSession: number | null
  denyCartography: (session: number) => void
  login: (csrfToken: string, user: User) => void
  enterDemo: () => void
  logout: () => void
  finishRestore: () => void
}
// The session itself is an HttpOnly cookie that scripts cannot read. Memory holds only the
// profile and the CSRF token, which a reload recovers from GET /auth/session.
try { localStorage.removeItem('shadai-auth') } catch { /* Storage may be disabled. */ }
export const useAuthStore = create<AuthState>((set) => ({
  csrfToken: null, user: null, isAuthenticated: false, mode: 'live', session: 0, restoring: true,
  cartographyDeniedSession: null,
  denyCartography: (session) => set(s => s.session === session ? { cartographyDeniedSession: session } : s),
  login: (csrfToken, user) => set(s => ({ csrfToken, user, isAuthenticated: true, mode: 'live', session: s.session + 1, restoring: false, cartographyDeniedSession: null })),
  enterDemo: () => set(s => ({ csrfToken: null, user: { user_id: 'demo-reviewer', username: 'Demo reviewer', email: null, role: 'admin', is_active: true }, isAuthenticated: true, mode: 'demo', session: s.session + 1, restoring: false, cartographyDeniedSession: null })),
  logout: () => set(s => ({ csrfToken: null, user: null, isAuthenticated: false, mode: 'live', session: s.session + 1, restoring: false, cartographyDeniedSession: null })),
  finishRestore: () => set({ restoring: false }),
}))
