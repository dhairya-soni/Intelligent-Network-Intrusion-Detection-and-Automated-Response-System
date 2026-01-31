import { useState, useEffect } from 'react'
import Dashboard from './Dashboard'
import AlertsList from './AlertsList'
import { api } from './api'

function App() {
  const [view, setView] = useState('dashboard')
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Fetch data
  const fetchData = async () => {
    try {
      const [alertsRes, statsRes] = await Promise.all([
        api.getAlerts(),
        api.getStats()
      ])
      
      setAlerts(alertsRes.data)
      setStats(statsRes.data)
      setError(null)
    } catch (err) {
      console.error('Error fetching data:', err)
      setError('Failed to fetch data. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  // Initial load
  useEffect(() => {
    fetchData()
  }, [])

  // Auto-refresh every 3 seconds
  useEffect(() => {
    const interval = setInterval(fetchData, 3000)
    return () => clearInterval(interval)
  }, [])

  const handleClearAlerts = async () => {
    if (window.confirm('Clear all alerts?')) {
      try {
        await api.clearAlerts()
        await fetchData()
      } catch (err) {
        console.error('Error clearing alerts:', err)
      }
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 sticky top-0 z-50 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="text-3xl">🛡️</div>
              <div>
                <h1 className="text-2xl font-bold text-white">INIDARS</h1>
                <p className="text-xs text-slate-400">Intelligent Network Intrusion Detection</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <button
                onClick={() => setView('dashboard')}
                className={`px-4 py-2 rounded-lg transition-colors ${
                  view === 'dashboard'
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-300 hover:bg-slate-700'
                }`}
              >
                📊 Dashboard
              </button>
              
              <button
                onClick={() => setView('alerts')}
                className={`px-4 py-2 rounded-lg transition-colors relative ${
                  view === 'alerts'
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-300 hover:bg-slate-700'
                }`}
              >
                🚨 Alerts
                {stats?.total_alerts > 0 && (
                  <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs px-2 py-0.5 rounded-full">
                    {stats.total_alerts}
                  </span>
                )}
              </button>
              
              <button
                onClick={fetchData}
                className="p-2 text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
                title="Refresh"
              >
                🔄
              </button>
              
              <button
                onClick={handleClearAlerts}
                className="p-2 text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
                title="Clear all alerts"
              >
                🗑️
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded-lg mb-6">
            <p className="font-semibold">⚠️ Error</p>
            <p className="text-sm">{error}</p>
          </div>
        )}
        
        {loading ? (
          <div className="text-center py-20">
            <div className="text-6xl mb-4">⏳</div>
            <p className="text-slate-400">Loading...</p>
          </div>
        ) : (
          <>
            {view === 'dashboard' && <Dashboard stats={stats} alerts={alerts} />}
            {view === 'alerts' && <AlertsList alerts={alerts} onRefresh={fetchData} />}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-slate-800 border-t border-slate-700 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <p className="text-center text-slate-400 text-sm">
            INIDARS MVP v1.0 - Powered by ML + Rule-based Detection
          </p>
        </div>
      </footer>
    </div>
  )
}

export default App
