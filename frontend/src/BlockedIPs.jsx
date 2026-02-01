import { useState, useEffect } from 'react'
import { 
  Ban, 
  Shield, 
  AlertTriangle,
  Unlock,
  RefreshCw
} from 'lucide-react'
import { api } from './api'

function BlockedIPs({ onRefresh }) {
  const [blocked, setBlocked] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchBlocked()
  }, [])

  const fetchBlocked = async () => {
    try {
      const res = await api.getBlockedIPs()
      setBlocked(res.data)
    } catch (err) {
      console.error('Error fetching blocked IPs:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleUnblock = async (ip) => {
    if (!window.confirm(`Unblock IP address ${ip}?`)) return
    try {
      await api.unblockIP(ip)
      fetchBlocked()
      if (onRefresh) onRefresh()
    } catch (err) {
      alert('Failed to unblock IP')
    }
  }

  if (loading) return (
    <div className="h-64 flex items-center justify-center text-slate-500">
      <div className="w-8 h-8 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin mr-3"></div>
      Loading blocked IPs...
    </div>
  )

  return (
    <div className="space-y-6">
      {/* Stats Header */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-card p-6 flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center">
            <Ban className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-white">{blocked.length}</p>
            <p className="text-sm text-slate-400">Active Blocks</p>
          </div>
        </div>
        
        <div className="glass-card p-6 flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <p className="text-2xl font-bold text-white">
              {blocked.reduce((sum, item) => sum + item.alert_count, 0)}
            </p>
            <p className="text-sm text-slate-400">Total Blocked Events</p>
          </div>
        </div>

        <div className="glass-card p-6 flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
            <Shield className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <p className="text-lg font-bold text-emerald-400">Active</p>
            <p className="text-sm text-slate-400">Protection Status</p>
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="glass-card overflow-hidden">
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white">Blocked IP Addresses</h3>
            <p className="text-sm text-slate-400 mt-1">All traffic from these sources is currently rejected</p>
          </div>
          <button 
            onClick={fetchBlocked}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-sm text-slate-300 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>

        {blocked.length === 0 ? (
          <div className="h-64 flex flex-col items-center justify-center text-slate-500">
            <Shield className="w-12 h-12 mb-3 text-emerald-500/50" />
            <p className="text-sm font-medium">No IPs currently blocked</p>
            <p className="text-xs mt-1">Blocked IPs will appear here</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-white/5">
                <tr>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">IP Address</th>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Blocked At</th>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Reason</th>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Alert Count</th>
                  <th className="text-right py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {blocked.map((item) => (
                  <tr key={item.ip} className="hover:bg-white/5 transition-colors">
                    <td className="py-4 px-6">
                      <code className="text-red-400 font-mono font-medium text-sm bg-red-500/10 px-3 py-1 rounded-lg border border-red-500/20">
                        {item.ip}
                      </code>
                    </td>
                    <td className="py-4 px-6 text-sm text-slate-400">
                      {item.blocked_at ? new Date(item.blocked_at).toLocaleString() : 'Unknown'}
                    </td>
                    <td className="py-4 px-6 text-sm text-slate-400 max-w-xs truncate">
                      {item.reason}
                    </td>
                    <td className="py-4 px-6">
                      <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
                        {item.alert_count} alerts
                      </span>
                    </td>
                    <td className="py-4 px-6 text-right">
                      <button
                        onClick={() => handleUnblock(item.ip)}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 transition-colors text-sm font-medium"
                      >
                        <Unlock className="w-4 h-4" />
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

export default BlockedIPs