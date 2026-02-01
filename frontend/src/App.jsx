import { useState, useEffect } from 'react'
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Ban, 
  Activity, 
  RefreshCw, 
  Shield,
  Menu,
  Bell
} from 'lucide-react'
import Dashboard from './Dashboard'
import AlertsList from './AlertsList'
import BlockedIPs from './BlockedIPs'
import { api } from './api'

function App() {
  const [view, setView] = useState('dashboard')
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [lastUpdate, setLastUpdate] = useState(new Date())

  const fetchData = async () => {
    try {
      const [alertsRes, statsRes, modelRes] = await Promise.all([
        api.getAlerts(),
        api.getStats(),
        api.getModelInfo()
      ])
      setAlerts(alertsRes.data)
      setStats({
        ...statsRes.data,
        model_info: modelRes.data.model
      })
      setError(null)
    } catch (err) {
      console.error('Error fetching data:', err)
      setError('Failed to fetch data. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 3000)
    return () => clearInterval(interval)
  }, [])

  const navigation = [
    { 
      id: 'dashboard', 
      label: 'Dashboard', 
      icon: LayoutDashboard,
      count: null 
    },
    { 
      id: 'alerts', 
      label: 'Threat Alerts', 
      icon: ShieldAlert,
      count: stats?.total_alerts 
    },
    { 
      id: 'blocked', 
      label: 'Blocked IPs', 
      icon: Ban,
      count: stats?.blocked_ips_count 
    }
  ]

  return (
    <div className="flex h-screen bg-[#0a0e1f] overflow-hidden">
      {/* Sidebar */}
      <aside className={`${sidebarOpen ? 'w-64' : 'w-20'} glass-card border-r border-white/10 flex flex-col transition-all duration-300`}>
        {/* Logo */}
        <div className="h-16 flex items-center gap-3 px-6 border-b border-white/10">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-500/30">
            <Shield className="w-5 h-5 text-white" />
          </div>
          {sidebarOpen && (
            <div>
              <h1 className="font-bold text-lg text-white tracking-tight">INIDARS</h1>
              <p className="text-xs text-slate-400">Network Defense</p>
            </div>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4">
          <div className="mb-6">
            <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-3 px-4">
              {sidebarOpen ? 'Main Menu' : 'Menu'}
            </p>
            {navigation.map((item) => {
              const Icon = item.icon
              return (
                <button
                  key={item.id}
                  onClick={() => setView(item.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all mb-1 ${
                    view === item.id 
                      ? 'bg-gradient-to-r from-indigo-600/20 to-purple-600/10 border border-indigo-500/30 text-white' 
                      : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  {sidebarOpen && (
                    <>
                      <span className="flex-1 text-sm font-medium text-left">{item.label}</span>
                      {item.count > 0 && (
                        <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs font-bold rounded-full border border-red-500/30">
                          {item.count}
                        </span>
                      )}
                    </>
                  )}
                </button>
              )
            })}
          </div>

          {/* System Status */}
          {sidebarOpen && (
            <div className="mt-auto p-4 rounded-xl bg-white/5 border border-white/10">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                <span className="text-xs font-medium text-emerald-400">System Active</span>
              </div>
              <p className="text-xs text-slate-500">v2.0.1 Build 2026</p>
            </div>
          )}
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <header className="h-16 glass-card border-b border-white/10 flex items-center justify-between px-6 z-10">
          <div className="flex items-center gap-4">
            <button 
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
            >
              <Menu className="w-5 h-5" />
            </button>
            
            <div className="h-6 w-px bg-white/10"></div>
            
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Activity className="w-4 h-4" />
              <span>Last updated: {lastUpdate.toLocaleTimeString()}</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchData}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-sm font-medium text-slate-300 hover:text-white transition-all"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
            
            <div className="h-6 w-px bg-white/10"></div>
            
            <button className="p-2 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white relative">
              <Bell className="w-5 h-5" />
              {stats?.total_alerts > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
              )}
            </button>
          </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 overflow-auto p-6">
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 flex items-center gap-3">
              <ShieldAlert className="w-5 h-5" />
              {error}
            </div>
          )}
          
          {loading ? (
            <div className="h-full flex flex-col items-center justify-center text-slate-500">
              <div className="w-12 h-12 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin mb-4"></div>
              <p className="text-sm font-medium">Initializing Security Engine...</p>
            </div>
          ) : (
            <div className="fade-in">
              {view === 'dashboard' && <Dashboard stats={stats} alerts={alerts} />}
              {view === 'alerts' && <AlertsList alerts={alerts} onRefresh={fetchData} />}
              {view === 'blocked' && <BlockedIPs onRefresh={fetchData} />}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}

export default App