import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const links = [
  { to: '/', label: 'Dashboard' },
  { to: '/alerts', label: 'Alerts' },
  { to: '/cases', label: 'Cases' },
  { to: '/triage', label: 'Triage' },
  { to: '/status', label: 'System Status' },
]

export default function Nav() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  async function handleLogout() {
    await logout()
    navigate('/login')
  }

  return (
    <nav className="app-nav">
      <span className="app-nav-brand">SentinelX</span>
      <div className="app-nav-links">
        {links.map(({ to, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              isActive ? 'app-nav-link active' : 'app-nav-link'
            }
          >
            {label}
          </NavLink>
        ))}
      </div>
      {user && (
        <div className="app-nav-user">
          <span className="user-badge">
            <span className="user-name">{user.username}</span>
            <span className={`user-role-badge ${user.role}`}>{user.role}</span>
          </span>
          <button
            type="button"
            className="btn-logout"
            onClick={handleLogout}
            title="Sign out"
          >
            Logout
          </button>
        </div>
      )}
    </nav>
  )
}
