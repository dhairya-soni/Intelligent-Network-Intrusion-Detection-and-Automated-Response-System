import { useState, useEffect } from 'react'
import { 
  X, 
  Ban, 
  Shield, 
  Unlock,
  Clock,
  AlertTriangle,
  Activity
} from 'lucide-react'
import { api } from './api'

function IPHistoryModal({ ip, onClose }) {
  const [history, setHistory] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    fetchHistory()
  }, [ip])

  const fetchHistory = async () => {
    try {
      const res = await api.getIPHistory(ip)
      setHistory(res.data)
    } catch (err) {
      console.error('Error fetching IP history:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleBlock = async () => {
    if (!window.confirm(`Block IP ${ip}?`)) return
    try {
      await api.blockIP(ip, 'Blocked from investigation view')
      fetchHistory()
    } catch (err) {
      alert('Failed to block IP')
    }
  }

  const handleUnblock = async () => {
    if (!window.confirm(`Unblock IP ${ip}?`)) return
    try {
      await api.unblockIP(ip)
      fetchHistory()
    } catch (err) {
      alert('Failed to unblock IP')
    }
  }

  if (loading) return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="w-8 h-8 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin"></div>
    </div>
  )

  if (!history) return null

  const { statistics, alerts, actions } = history

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="glass-card w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-white/10 flex items-center justify-between bg-white/5">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
              <Shield className="w-6 h-6 text-indigo-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">IP Investigation</h2>
              <div className="flex items-center gap-3 mt-1">
                <code className="text-lg font-mono text-indigo-400">{ip}</code>
                {statistics.is_blocked ? (
                  <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/30 flex items-center gap-1">
                    <Ban className="w-3 h-3" />
                    BLOCKED
                  </span>
                ) : (
                  <span className="px-2 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                    <Activity className="w-3 h-3" />
                    ACTIVE
                  </span>
                )}
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-white/10 bg-white/5">
          {['overview', 'alerts', 'timeline', 'actions'].map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-6 py-4 text-sm font-medium capitalize transition-colors relative ${
                activeTab === tab ? 'text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab}
              {activeTab === tab && (
                <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-indigo-500 to-purple-500"></div>
              )}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatBox label="Total Alerts" value={statistics.total_alerts} color="indigo" />
                <StatBox label="Critical" value={statistics.severity_breakdown.CRITICAL} color="red" />
                <StatBox label="High" value={statistics.severity_breakdown.HIGH} color="orange" />
                <StatBox label="Status" value={statistics.is_blocked ? 'Blocked' : 'Active'} color={statistics.is_blocked ? 'red' : 'green'} />
              </div>

              <div className="glass-card p-6 bg-white/5">
                <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-4">Threat Types Detected</h3>
                <div className="flex flex-wrap gap-2">
                  {statistics.threat_types.length > 0 ? statistics.threat_types.map(type => (
                    <span key={type} className="px-3 py-1.5 rounded-lg text-sm bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                      {type}
                    </span>
                  )) : (
                    <span className="text-slate-500 text-sm">No threats detected</span>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="glass-card p-4 bg-white/5">
                  <p className="text-slate-400 mb-1">First Seen</p>
                  <p className="text-white font-medium">
                    {statistics.first_seen ? new Date(statistics.first_seen).toLocaleString() : 'Never'}
                  </p>
                </div>
                <div className="glass-card p-4 bg-white/5">
                  <p className="text-slate-400 mb-1">Last Seen</p>
                  <p className="text-white font-medium">
                    {statistics.last_seen ? new Date(statistics.last_seen).toLocaleString() : 'Never'}
                  </p>
                </div>
              </div>

              <div className="flex gap-3 pt-4">
                {statistics.is_blocked ? (
                  <button onClick={handleUnblock} className="flex-1 py-3 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-white font-medium transition-colors flex items-center justify-center gap-2">
                    <Unlock className="w-4 h-4" />
                    Unblock IP
                  </button>
                ) : (
                  <button onClick={handleBlock} className="flex-1 py-3 rounded-xl bg-red-500 hover:bg-red-600 text-white font-medium transition-colors flex items-center justify-center gap-2">
                    <Ban className="w-4 h-4" />
                    Block IP
                  </button>
                )}
              </div>
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-3">
              {alerts.length === 0 ? (
                <div className="text-center py-12 text-slate-500">
                  <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No alerts for this IP</p>
                </div>
              ) : (
                alerts.map(alert => (
                  <div key={alert.id} className="glass-card p-4 bg-white/5 hover:bg-white/10 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        alert.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                        alert.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30' :
                        alert.severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30' :
                        'bg-green-500/10 text-green-400 border border-green-500/30'
                      }`}>
                        {alert.severity}
                      </span>
                      <span className="text-xs text-slate-500">
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="font-medium text-white mb-1">{alert.threat_type}</p>
                    <p className="text-sm text-slate-400 mb-2">{alert.description}</p>
                    <div className="flex items-center gap-4 text-xs text-slate-500">
                      <span>ML Score: <span className="text-white">{(alert.ml_score * 100).toFixed(0)}%</span></span>
                      <span>Rule Match: {alert.rule_matched ? 'Yes' : 'No'}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="space-y-0">
              {alerts.slice(0, 10).map((alert, idx) => (
                <div key={alert.id} className="flex gap-4 pb-8 relative">
                  {idx !== alerts.length - 1 && (
                    <div className="absolute left-3.5 top-8 bottom-0 w-px bg-white/10"></div>
                  )}
                  <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${
                    alert.severity === 'CRITICAL' ? 'bg-red-500' :
                    alert.severity === 'HIGH' ? 'bg-orange-500' :
                    alert.severity === 'MEDIUM' ? 'bg-yellow-500' :
                    'bg-green-500'
                  }`}>
                    <AlertTriangle className="w-4 h-4 text-white" />
                  </div>
                  <div>
                    <p className="text-sm text-slate-400">
                      {new Date(alert.timestamp).toLocaleString()}
                    </p>
                    <p className="font-medium text-white mt-1">{alert.threat_type}</p>
                    <p className="text-sm text-slate-500 mt-1">{alert.description}</p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'actions' && (
            <div className="space-y-2">
              {actions.length === 0 ? (
                <div className="text-center py-12 text-slate-500">
                  <Clock className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No actions recorded</p>
                </div>
              ) : (
                actions.map(action => (
                  <div key={action.id} className="glass-card p-3 bg-white/5 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        action.action.includes('BLOCK') ? 'bg-red-500' :
                        action.action.includes('UNBLOCK') ? 'bg-emerald-500' :
                        'bg-indigo-500'
                      }`}></div>
                      <div>
                        <p className="text-sm text-white font-medium">{action.action}</p>
                        <p className="text-xs text-slate-500">{action.details}</p>
                      </div>
                    </div>
                    <span className="text-xs text-slate-500 font-mono">
                      {new Date(action.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function StatBox({ label, value, color }) {
  const colors = {
    indigo: 'bg-indigo-500/10 border-indigo-500/30 text-indigo-400',
    red: 'bg-red-500/10 border-red-500/30 text-red-400',
    orange: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
    green: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
  }
  
  return (
    <div className={`${colors[color]} border rounded-xl p-4 text-center`}>
      <p className="text-2xl font-bold text-white mb-1">{value}</p>
      <p className="text-xs text-slate-400 uppercase tracking-wider">{label}</p>
    </div>
  )
}

export default IPHistoryModal