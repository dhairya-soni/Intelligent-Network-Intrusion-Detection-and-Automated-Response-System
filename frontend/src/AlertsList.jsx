import { useState } from 'react'
import { api } from './api'
import IPHistoryModal from './IPHistoryModal'

function AlertsList({ alerts, onRefresh }) {
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [investigatingIP, setInvestigatingIP] = useState(null)
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [blockLoading, setBlockLoading] = useState(null)

  const filteredAlerts = filterSeverity === 'all'
    ? alerts
    : alerts.filter(a => a.severity === filterSeverity)

  const handleBlockIP = async (ip, e) => {
    e.stopPropagation()
    if (!window.confirm(`Block IP ${ip}? This will reject all future events from this IP.`)) return
    
    setBlockLoading(ip)
    try {
      await api.blockIP(ip, `Blocked from alert view`, 'permanent')
      alert(`IP ${ip} blocked successfully`)
      if (onRefresh) onRefresh()
    } catch (err) {
      alert('Failed to block IP')
    } finally {
      setBlockLoading(null)
    }
  }

  const handleInvestigate = (ip, e) => {
    e.stopPropagation()
    setInvestigatingIP(ip)
  }

  const handleDelete = async (id, e) => {
    e.stopPropagation()
    if (!window.confirm('Delete this alert?')) return
    try {
      await api.deleteAlert(id)
      if (onRefresh) onRefresh()
    } catch (err) {
      alert('Failed to delete alert')
    }
  }

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center space-x-4">
            <span className="text-sm text-slate-400">Filter:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All ({alerts.length})</option>
              <option value="CRITICAL">Critical ({alerts.filter(a => a.severity === 'CRITICAL').length})</option>
              <option value="HIGH">High ({alerts.filter(a => a.severity === 'HIGH').length})</option>
              <option value="MEDIUM">Medium ({alerts.filter(a => a.severity === 'MEDIUM').length})</option>
              <option value="LOW">Low ({alerts.filter(a => a.severity === 'LOW').length})</option>
            </select>
          </div>
          
          <div className="text-sm text-slate-400">
            Showing {filteredAlerts.length} of {alerts.length} alerts
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
        {filteredAlerts.length === 0 ? (
          <div className="text-center py-12">
            <div className="text-6xl mb-4">🎉</div>
            <p className="text-slate-400">No alerts found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Time</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Threat</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Source IP</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="hover:bg-slate-700/50 transition-colors group"
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-sm font-medium text-white">{alert.threat_type}</p>
                      <p className="text-xs text-slate-500">{(alert.ml_score * 100).toFixed(0)}% confidence</p>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-sm text-slate-300">
                      {alert.source_ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={(e) => handleInvestigate(alert.source_ip, e)}
                          className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded transition-colors"
                          title="View IP history"
                        >
                          🔍 Investigate
                        </button>
                        <button
                          onClick={(e) => handleBlockIP(alert.source_ip, e)}
                          disabled={blockLoading === alert.source_ip}
                          className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors disabled:opacity-50"
                          title="Block this IP"
                        >
                          {blockLoading === alert.source_ip ? '...' : '🚫 Block'}
                        </button>
                        <button
                          onClick={(e) => handleDelete(alert.id, e)}
                          className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white text-xs rounded transition-colors"
                          title="Delete alert"
                        >
                          🗑️
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modals */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onBlock={(ip) => handleBlockIP(ip, { stopPropagation: () => {} })}
          onInvestigate={(ip) => setInvestigatingIP(ip)}
        />
      )}
      
      {investigatingIP && (
        <IPHistoryModal
          ip={investigatingIP}
          onClose={() => setInvestigatingIP(null)}
        />
      )}
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
    <span className={`px-2 py-1 rounded text-xs font-bold text-white ${colors[severity] || 'bg-gray-600'}`}>
      {severity}
    </span>
  )
}

// Keep your existing AlertDetailModal or use this simplified version
function AlertDetailModal({ alert, onClose, onBlock, onInvestigate }) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-800 rounded-lg border border-slate-700 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-slate-700 flex items-center justify-between">
          <h2 className="text-xl font-bold">Alert Details</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-2xl">×</button>
        </div>
        
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <SeverityBadge severity={alert.severity} />
            <span className="text-sm text-slate-400">{new Date(alert.timestamp).toLocaleString()}</span>
          </div>

          <h3 className="text-lg font-semibold">{alert.threat_type}</h3>
          <p className="text-slate-300">{alert.description}</p>

          <div className="grid grid-cols-2 gap-4 bg-slate-900/50 p-4 rounded-lg">
            <div>
              <p className="text-xs text-slate-500">Source IP</p>
              <p className="font-mono text-lg">{alert.source_ip}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Destination</p>
              <p className="font-mono">{alert.dest_ip}:{alert.dest_port}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">ML Score</p>
              <p>{(alert.ml_score * 100).toFixed(1)}%</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Protocol</p>
              <p>{alert.protocol.toUpperCase()}</p>
            </div>
          </div>

          <div className="flex space-x-3 pt-4">
            <button 
              onClick={() => onInvestigate(alert.source_ip)}
              className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg"
            >
              🔍 Investigate IP
            </button>
            <button 
              onClick={() => onBlock(alert.source_ip)}
              className="flex-1 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg"
            >
              🚫 Block IP
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AlertsList