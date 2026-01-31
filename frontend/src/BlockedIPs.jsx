import { useState, useEffect } from 'react'
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
    if (!window.confirm(`Unblock ${ip}?`)) return
    try {
      await api.unblockIP(ip)
      fetchBlocked()
      if (onRefresh) onRefresh()
    } catch (err) {
      alert('Failed to unblock IP')
    }
  }

  if (loading) return <div className="text-center py-8 text-slate-400">Loading...</div>

  return (
    <div className="space-y-6">
      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-bold text-white">🚫 Blocked IPs</h2>
            <p className="text-slate-400 text-sm mt-1">
              {blocked.length} IP(s) currently blocked
            </p>
          </div>
          <button 
            onClick={fetchBlocked}
            className="p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
          >
            🔄 Refresh
          </button>
        </div>

        {blocked.length === 0 ? (
          <div className="text-center py-12 bg-slate-900/50 rounded-lg">
            <div className="text-6xl mb-4">✅</div>
            <p className="text-slate-400">No IPs currently blocked</p>
            <p className="text-sm text-slate-500 mt-2">Block IPs from the alerts view</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Blocked At</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Reason</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Alerts</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {blocked.map((item) => (
                  <tr key={item.ip} className="hover:bg-slate-700/50">
                    <td className="px-6 py-4 font-mono text-red-400 font-semibold">{item.ip}</td>
                    <td className="px-6 py-4 text-sm text-slate-300">
                      {item.blocked_at ? new Date(item.blocked_at).toLocaleString() : 'Unknown'}
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-400 max-w-xs truncate">
                      {item.reason}
                    </td>
                    <td className="px-6 py-4">
                      <span className="bg-red-900/50 text-red-200 px-2 py-1 rounded-full text-xs">
                        {item.alert_count} alerts
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => handleUnblock(item.ip)}
                        className="text-green-400 hover:text-green-300 font-medium text-sm"
                      >
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

      {/* Quick Stats */}
      {blocked.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <p className="text-slate-400 text-sm">Total Blocked</p>
            <p className="text-3xl font-bold text-white mt-1">{blocked.length}</p>
          </div>
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <p className="text-slate-400 text-sm">Total Alerts</p>
            <p className="text-3xl font-bold text-red-400 mt-1">
              {blocked.reduce((sum, item) => sum + item.alert_count, 0)}
            </p>
          </div>
          <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <p className="text-slate-400 text-sm">Auto-Protection</p>
            <p className="text-lg font-bold text-green-400 mt-1">Active</p>
            <p className="text-xs text-slate-500">Blocking new events</p>
          </div>
        </div>
      )}
    </div>
  )
}

export default BlockedIPs