import { useState, useEffect } from 'react'
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
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="text-white text-xl">Loading...</div>
    </div>
  )

  if (!history) return null

  const { statistics, alerts, actions } = history

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-800 rounded-xl border border-slate-700 max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-slate-700 flex items-center justify-between bg-slate-900/50">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
              🕵️ IP Investigation: {ip}
              {statistics.is_blocked && (
                <span className="px-2 py-1 bg-red-600 text-xs rounded-full">BLOCKED</span>
              )}
            </h2>
            <p className="text-slate-400 text-sm mt-1">
              First seen: {statistics.first_seen ? new Date(statistics.first_seen).toLocaleString() : 'Never'} | 
              Last seen: {statistics.last_seen ? new Date(statistics.last_seen).toLocaleString() : 'Never'}
            </p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-2xl">×</button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-slate-700 bg-slate-800">
          {['overview', 'alerts', 'timeline', 'actions'].map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-6 py-3 capitalize ${activeTab === tab ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-700'}`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatBox label="Total Alerts" value={statistics.total_alerts} color="blue" />
                <StatBox label="Critical" value={statistics.severity_breakdown.CRITICAL} color="red" />
                <StatBox label="High" value={statistics.severity_breakdown.HIGH} color="orange" />
                <StatBox label="Status" value={statistics.is_blocked ? 'Blocked' : 'Active'} color={statistics.is_blocked ? 'red' : 'green'} />
              </div>

              {/* Threat Types */}
              <div className="bg-slate-900/50 rounded-lg p-4">
                <h3 className="text-lg font-semibold mb-3">Detected Threat Types</h3>
                <div className="flex flex-wrap gap-2">
                  {statistics.threat_types.length > 0 ? statistics.threat_types.map(type => (
                    <span key={type} className="px-3 py-1 bg-slate-700 rounded-full text-sm text-yellow-400">
                      ⚠️ {type}
                    </span>
                  )) : (
                    <span className="text-slate-500">No threats detected</span>
                  )}
                </div>
              </div>

              {/* Quick Actions */}
              <div className="flex gap-3">
                {statistics.is_blocked ? (
                  <button onClick={handleUnblock} className="flex-1 bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-semibold">
                    ✅ Unblock IP
                  </button>
                ) : (
                  <button onClick={handleBlock} className="flex-1 bg-red-600 hover:bg-red-700 text-white py-3 rounded-lg font-semibold">
                    🚫 Block IP
                  </button>
                )}
              </div>
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-3">
              {alerts.length === 0 ? (
                <p className="text-center text-slate-500 py-8">No alerts for this IP</p>
              ) : (
                alerts.map(alert => (
                  <div key={alert.id} className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                    <div className="flex items-center justify-between mb-2">
                      <SeverityBadge severity={alert.severity} />
                      <span className="text-sm text-slate-500">
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="font-semibold text-lg mb-1">{alert.threat_type}</p>
                    <p className="text-sm text-slate-400 mb-2">{alert.description}</p>
                    <div className="flex items-center gap-4 text-sm text-slate-500">
                      <span>ML Score: {(alert.ml_score * 100).toFixed(0)}%</span>
                      <span>Rule: {alert.rule_matched ? '✅' : '❌'}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="space-y-3">
              {alerts.slice(0, 10).map((alert, idx) => (
                <div key={alert.id} className="flex items-start gap-4">
                  <div className="flex flex-col items-center">
                    <div className={`w-3 h-3 rounded-full ${getSeverityColor(alert.severity)}`} />
                    {idx !== alerts.length - 1 && <div className="w-0.5 h-full bg-slate-700 mt-2" />}
                  </div>
                  <div className="pb-6">
                    <p className="text-sm text-slate-400">{new Date(alert.timestamp).toLocaleString()}</p>
                    <p className="font-semibold">{alert.threat_type}</p>
                    <p className="text-sm text-slate-500">{alert.description}</p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'actions' && (
            <div className="space-y-2">
              {actions.length === 0 ? (
                <p className="text-center text-slate-500 py-8">No actions recorded</p>
              ) : (
                actions.map(action => (
                  <div key={action.id} className="bg-slate-900/50 rounded p-3 flex justify-between items-center">
                    <div>
                      <span className={`px-2 py-1 rounded text-xs ${getActionColor(action.action)}`}>
                        {action.action}
                      </span>
                      <p className="text-sm text-slate-400 mt-1">{action.details}</p>
                    </div>
                    <span className="text-xs text-slate-500">
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
    blue: 'bg-blue-900/30 border-blue-700',
    red: 'bg-red-900/30 border-red-700',
    orange: 'bg-orange-900/30 border-orange-700',
    green: 'bg-green-900/30 border-green-700'
  }
  
  return (
    <div className={`${colors[color]} border rounded-lg p-4 text-center`}>
      <p className="text-2xl font-bold text-white">{value}</p>
      <p className="text-xs text-slate-400 uppercase tracking-wider">{label}</p>
    </div>
  )
}

function SeverityBadge({ severity }) {
  const colors = {
    CRITICAL: 'bg-red-600',
    HIGH: 'bg-orange-600',
    MEDIUM: 'bg-yellow-600',
    LOW: 'bg-green-600'
  }
  return (
    <span className={`${colors[severity]} px-2 py-1 rounded text-xs font-bold text-white`}>
      {severity}
    </span>
  )
}

function getSeverityColor(severity) {
  const colors = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-yellow-500',
    LOW: 'bg-green-500'
  }
  return colors[severity] || 'bg-slate-500'
}

function getActionColor(action) {
  if ('BLOCK' in action) return 'bg-red-900 text-red-200'
  if ('ALERT' in action) return 'bg-yellow-900 text-yellow-200'
  return 'bg-slate-700 text-slate-300'
}

export default IPHistoryModal