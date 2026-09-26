import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import ErrorBoundary from '@/components/ui/ErrorBoundary'
import AppShell from '@/components/layout/AppShell'
import Login from '@/pages/Login'
import SsoCallback from '@/pages/SsoCallback'
import DemoEntry from '@/pages/DemoEntry'
import Dashboard from '@/pages/Dashboard'
import DiscoveryList from '@/pages/DiscoveryList'
import DetectionDetail from '@/pages/DetectionDetail'
import UserView from '@/pages/UserView'
import OAuthApps from '@/pages/OAuthApps'
import Extensions from '@/pages/Extensions'
import LocalAI from '@/pages/LocalAI'
import Governance from '@/pages/Governance'
import Catalog from '@/pages/Catalog'
import Sources from '@/pages/Sources'
import Settings from '@/pages/Settings'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/login" element={<Login />} /><Route path="/auth/callback" element={<SsoCallback />} /><Route path="/demo" element={<DemoEntry />} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <AppShell>
                <ErrorBoundary>
                  <Routes>
                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/discoveries" element={<DiscoveryList />} />
                    <Route path="/discoveries/:id" element={<DetectionDetail />} />
                    <Route path="/users" element={<UserView />} />
                    <Route path="/oauth-apps" element={<OAuthApps />} />
                    <Route path="/extensions" element={<Extensions />} />
                    <Route path="/local-ai" element={<LocalAI />} />
                    <Route path="/governance" element={<Governance />} />
                    <Route path="/catalog" element={<Catalog />} />
                    <Route path="/sources" element={<Sources />} />
                    <Route path="/settings" element={<Settings />} /><Route path="*" element={<Navigate to="/dashboard" replace />} />
                  </Routes>
                </ErrorBoundary>
              </AppShell>
            </ProtectedRoute>
          }
        />
      </Routes>
    </ErrorBoundary>
  )
}
