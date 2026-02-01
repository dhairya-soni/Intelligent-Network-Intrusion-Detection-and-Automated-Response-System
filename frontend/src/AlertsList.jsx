import { useState } from 'react'
import { 
  Search, 
  Filter, 
  ShieldAlert, 
  Trash2, 
  Ban, 
  Search as SearchIcon,
  X
} from 'lucide-react'
import { api } from './api'
import IPHistoryModal from './IPHistoryModal'

function AlertsList({ alerts, onRefresh }) {
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [investigatingIP, setInvestigatingIP] = useState(null)
  const [filterSeverity, setFilterSeverity] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [blockLoading, setBlockLoading] = useState(null)

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = filterSeverity === 'all' || alert.severity === filterSeverity
    const matchesSearch = searchQuery === '' || 
      alert.source_ip.includes(searchQuery) || 
      alert.threat_type.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesSeverity && matchesSearch
  })

  const handleBlockIP = async (ip, e) => {
    e.stopPropagation()
    if (!window.confirm(`Block IP address ${ip}? This will reject all future traffic from this source.`)) return
    
    setBlockLoading(ip)
    try {
      await api.blockIP(ip, 'Manual block from alerts view')
      onRefresh()
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
    if (!window.confirm('Delete this alert permanently?')) return
    try {
      await api.deleteAlert(id)
      onRefresh()
    } catch (err) {
      alert('Failed to delete alert')
    }
  }

  const getSeverityBadge = (severity) => {
    const styles = {
      CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/30',
      HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
      MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
      LOW: 'bg-green-500/10 text-green-400 border-green-500/30'
    }
    return styles[severity] || 'bg-slate-500/10 text-slate-400'
  }

  return (
    <div className="space-y-6">
      {/* Header & Filters */}
      <div className="glass-card p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4 flex-1">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by IP or threat type..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
              />
              {searchQuery && (
                <button 
                  onClick={() => setSearchQuery('')}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>

            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-slate-400" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50"
              >
                <option value="all">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          <div className="text-sm text-slate-400">
            Showing <span className="text-white font-medium">{filteredAlerts.length}</span> of <span className="text-white font-medium">{alerts.length}</span> alerts
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="glass-card overflow-hidden">
        {filteredAlerts.length === 0 ? (
          <div className="h-64 flex flex-col items-center justify-center text-slate-500">
            <ShieldAlert className="w-12 h-12 mb-3 opacity-50" />
            <p className="text-sm font-medium">No alerts found</p>
            <p className="text-xs mt-1">Try adjusting your filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-white/5 border-b border-white/10">
                <tr>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Severity</th>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Threat Type</th>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Source IP</th>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Details</th>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Time</th>
                  <th className="text-right py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredAlerts.map((alert) => (
                  <tr 
                    key={alert.id} 
                    className="hover:bg-white/5 transition-colors group"
                  >
                    <td className="py-4 px-6">
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getSeverityBadge(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <div>
                        <p className="text-white font-medium text-sm">{alert.threat_type}</p>
                        <p className="text-xs text-slate-500 mt-0.5">{alert.description}</p>
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <code className="text-sm text-indigo-400 font-mono bg-indigo-500/10 px-2 py-1 rounded">
                        {alert.source_ip}
                      </code>
                    </td>
                    <td className="py-4 px-6">
                      <div className="text-xs text-slate-400 space-y-1">
                        <p>Port: {alert.dest_port}</p>
                        <p>ML Score: <span className="text-white">{(alert.ml_score * 100).toFixed(0)}%</span></p>
                      </div>
                    </td>
                    <td className="py-4 px-6 text-sm text-slate-400">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={(e) => handleInvestigate(alert.source_ip, e)}
                          className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 border border-indigo-500/30 transition-colors"
                          title="Investigate IP"
                        >
                          <SearchIcon className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => handleBlockIP(alert.source_ip, e)}
                          disabled={blockLoading === alert.source_ip}
                          className="p-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 transition-colors disabled:opacity-50"
                          title="Block IP"
                        >
                          <Ban className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => handleDelete(alert.id, e)}
                          className="p-2 rounded-lg bg-slate-700/50 text-slate-400 hover:bg-slate-700 hover:text-white transition-colors"
                          title="Delete Alert"
                        >
                          <Trash2 className="w-4 h-4" />
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
      {investigatingIP && (
        <IPHistoryModal
          ip={investigatingIP}
          onClose={() => setInvestigatingIP(null)}
        />
      )}
    </div>
  )
}

export default AlertsList