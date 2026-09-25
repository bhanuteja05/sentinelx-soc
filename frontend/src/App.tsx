import { BrowserRouter, Route, Routes, Navigate, Outlet } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute from './components/ProtectedRoute'
import Nav from './components/Nav'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Cases from './pages/Cases'
import CaseDetail from './pages/CaseDetail'
import CreateCase from './pages/CreateCase'
import SystemStatus from './SystemStatus'
import Login from './pages/Login'

function AppLayout() {
  return (
    <ProtectedRoute>
      <div className="app-shell">
        <Nav />
        <main className="app-main">
          <Outlet />
        </main>
      </div>
    </ProtectedRoute>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<AppLayout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/cases/new" element={<CreateCase />} />
            <Route path="/cases/:id" element={<CaseDetail />} />
            <Route path="/status" element={<SystemStatus />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
