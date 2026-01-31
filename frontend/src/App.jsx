import { useState, useEffect } from 'react'
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

  const navButton = (id, label, icon, count = null) => (
    <button
      onClick={() => setView(id)}
      className={`px-4 py-2 rounded-lg transition-all flex items-center space-x-2 ${
        view === id
          ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30'
          : 'text-slate-300 hover:bg-slate-700'
      }`}
    >
      <span>{icon}</span>
      <span>{label}</span>
      {count !== null && count > 0 && (
        <span className="bg-red-500 text-white text-xs px-2 py-0.5 rounded-full">
          {count}
        </span>
      )}
    </button>
  )

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 sticky top-0 z-50 shadow-lg backdrop-blur-lg bg-opacity-95">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="text-3xl animate-pulse">🛡️</div>
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                  INIDARS
                </h1>
                <p className="text-xs text-slate-400">Intelligent Network Defense</p>
              </div>
            </div>
            
            <nav className="flex items-center space-x-2">
              {navButton('dashboard', 'Dashboard', '📊')}
              {navButton('alerts', 'Alerts', '🚨', stats?.total_alerts)}
              {navButton('blocked', 'Blocked', '🚫', stats?.blocked_ips_count)}
              
              <div className="h-6 w-px bg-slate-600 mx-2" />
              
              <button
                onClick={fetchData}
                className="p-2 text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
                title="Refresh now"
              >
                🔄
              </button>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded-lg mb-6 flex items-center">
            <span className="mr-2">⚠️</span>
            {error}
          </div>
        )}
        
        {loading ? (
          <div className="text-center py-20">
            <div className="inline-block animate-spin text-4xl mb-4">⏳</div>
            <p className="text-slate-400">Initializing Security Engine...</p>
          </div>
        ) : (
          <>
            {view === 'dashboard' && <Dashboard stats={stats} alerts={alerts} />}
            {view === 'alerts' && <AlertsList alerts={alerts} onRefresh={fetchData} />}
            {view === 'blocked' && <BlockedIPs onRefresh={fetchData} />}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-slate-800 border-t border-slate-700 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between text-sm text-slate-500">
            <p>INIDARS v2.0 | ML + Rule-based Detection</p>
            <p>Last update: {lastUpdate.toLocaleTimeString()}</p>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App