import { NavLink } from 'react-router-dom'

const links = [
  { to: '/', label: 'Dashboard' },
  { to: '/alerts', label: 'Alerts' },
  { to: '/cases', label: 'Cases' },
  { to: '/status', label: 'System Status' },
]

export default function Nav() {
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
    </nav>
  )
}
