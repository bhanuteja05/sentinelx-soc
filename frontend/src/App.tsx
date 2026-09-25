import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Nav from './components/Nav'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Cases from './pages/Cases'
import CaseDetail from './pages/CaseDetail'
import CreateCase from './pages/CreateCase'
import SystemStatus from './SystemStatus'

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <Nav />
        <main className="app-main">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/cases/new" element={<CreateCase />} />
            <Route path="/cases/:id" element={<CaseDetail />} />
            <Route path="/status" element={<SystemStatus />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
