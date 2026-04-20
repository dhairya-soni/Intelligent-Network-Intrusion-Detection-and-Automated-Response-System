import { useState } from 'react'
import {
  Search, Filter, ShieldAlert, Trash2, Ban,
  Search as SearchIcon, X, ChevronDown, ChevronUp,
  Zap, Globe, AlertTriangle, Download, FileText, Eraser
} from 'lucide-react'
import { api } from './api'
import IPHistoryModal from './IPHistoryModal'

// ─── helpers ──────────────────────────────────────────────────────────────────
const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/10 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-green-500/10 text-green-400 border-green-500/30',
}

const ABUSE_COLORS = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  LOW:      'text-blue-400 bg-blue-500/10 border-blue-500/30',
  CLEAN:    'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
}

// ─── Expandable explanation panel ─────────────────────────────────────────────
function ExplanationPanel({ alert }) {
  const [threatIntel, setThreatIntel] = useState(null)
  const [tiLoading, setTiLoading]     = useState(false)
  const [tiError, setTiError]         = useState(null)

  const explanation = alert.explanation
  const features    = explanation?.live_features || []

  const loadThreatIntel = async () => {
    if (threatIntel || tiLoading) return
    setTiLoading(true)
    try {
      const res = await api.getThreatIntel(alert.source_ip)
      setThreatIntel(res.data)
    } catch {
      setTiError('Lookup failed')
    } finally {
      setTiLoading(false)
    }
  }

  return (
    <tr className="bg-slate-900/60">
      <td colSpan={6} className="px-6 py-4">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Feature anomaly bars */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-indigo-400" />
              Why It Was Flagged
            </h4>
            {features.length > 0 ? (
              <div className="space-y-2.5">
                {features.map((f, i) => (
                  <div key={i}>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-xs text-slate-300 font-medium">{f.feature}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-500 tabular-nums">
                          val={f.value} | normal [{f.normal_low}–{f.normal_high}]
                        </span>
                        <span className={`text-xs font-bold tabular-nums ${
                          f.anomaly_score > 0.7 ? 'text-red-400' :
                          f.anomaly_score > 0.4 ? 'text-amber-400' : 'text-slate-400'
                        }`}>
                          {Math.round(f.anomaly_score * 100)}%
                        </span>
                      </div>
                    </div>
                    <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          f.anomaly_score > 0.7 ? 'bg-red-500' :
                          f.anomaly_score > 0.4 ? 'bg-amber-500' : 'bg-indigo-500'
                        }`}
                        style={{ width: `${f.anomaly_score * 100}%` }}
                      />
                    </div>
                    {f.anomaly_score > 0.4 && (
                      <p className="text-xs text-slate-500 mt-0.5">{f.description}</p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500">
                Triggered by rule-based detection. See threat type for details.
              </p>
            )}

            {/* Detection summary */}
            <div className="mt-4 pt-3 border-t border-white/10 grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-slate-500">ML Score</span>
                <div className="text-white font-semibold mt-0.5">
                  {Math.round(alert.ml_score * 100)}%
                </div>
              </div>
              <div>
                <span className="text-slate-500">Rule Match</span>
                <div className={`font-semibold mt-0.5 ${alert.rule_matched ? 'text-orange-400' : 'text-slate-400'}`}>
                  {alert.rule_matched ? 'Yes' : 'No'}
                </div>
              </div>
              <div>
                <span className="text-slate-500">Attack Category</span>
                <div className="text-white font-semibold mt-0.5">{alert.attack_category || '—'}</div>
              </div>
              <div>
                <span className="text-slate-500">Confidence</span>
                <div className="text-white font-semibold mt-0.5">{alert.confidence}%</div>
              </div>
            </div>
          </div>

          {/* Threat Intel panel */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-purple-400" />
              Threat Intelligence (AbuseIPDB)
            </h4>

            {!threatIntel && !tiLoading && !tiError && (
              <button
                onClick={loadThreatIntel}
                className="text-xs px-3 py-1.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors"
              >
                Look up {alert.source_ip}
              </button>
            )}

            {tiLoading && (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <div className="w-3 h-3 border border-purple-500/40 border-t-purple-400 rounded-full animate-spin" />
                Querying AbuseIPDB…
              </div>
            )}

            {tiError && (
              <p className="text-xs text-red-400">{tiError}</p>
            )}

            {threatIntel && !threatIntel.error && (
              <div className="space-y-2">
                {/* Abuse score badge */}
                <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold ${
                  ABUSE_COLORS[threatIntel.risk_level] || ABUSE_COLORS.CLEAN
                }`}>
                  <AlertTriangle className="w-3.5 h-3.5" />
                  {threatIntel.risk_level} — Abuse Score: {threatIntel.abuse_score}%
                </div>

                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs mt-3">
                  {[
                    ['Reports',     threatIntel.total_reports],
                    ['Country',     threatIntel.country],
                    ['ISP',         threatIntel.isp || '—'],
                    ['Usage Type',  threatIntel.usage_type || '—'],
                    ['Whitelisted', threatIntel.is_whitelisted ? 'Yes' : 'No'],
                    ['Last Report', threatIntel.last_reported
                      ? new Date(threatIntel.last_reported).toLocaleDateString()
                      : 'Never'],
                  ].map(([k, v]) => (
                    <div key={k}>
                      <span className="text-slate-500">{k}</span>
                      <div className="text-white font-medium mt-0.5 truncate">{v}</div>
                    </div>
                  ))}
                </div>

                <p className="text-xs text-slate-600 mt-1">Source: AbuseIPDB</p>
              </div>
            )}

            {threatIntel?.error === 'no_key' && (
              <div className="text-xs text-slate-500 space-y-1">
                <p className="text-amber-400 font-medium">API key not configured</p>
                <p>1. Register free at <span className="text-indigo-400">abuseipdb.com</span></p>
                <p>2. Set env var: <code className="text-indigo-300">ABUSEIPDB_KEY=your_key</code></p>
                <p>3. Restart backend</p>
              </div>
            )}

            {threatIntel?.is_private && (
              <p className="text-xs text-slate-500">Private/internal IP — no external lookup needed.</p>
            )}

            {/* Recommendation */}
            <div className="mt-4 pt-3 border-t border-white/10">
              <span className="text-xs text-slate-500">Recommendation</span>
              <p className="text-xs text-slate-300 mt-1">{alert.recommendation}</p>
            </div>
          </div>
        </div>
      </td>
    </tr>
  )
}

// ─── Main component ────────────────────────────────────────────────────────────
function AlertsList({ alerts, onRefresh }) {
  const [expandedId, setExpandedId]     = useState(null)
  const [investigatingIP, setInvestigatingIP] = useState(null)
  const [filterSeverity, setFilterSeverity]   = useState('all')
  const [searchQuery, setSearchQuery]         = useState('')
  const [blockLoading, setBlockLoading]       = useState(null)
  const [clearing, setClearing]               = useState(false)

  const handleClearAll = async () => {
    if (!window.confirm(`Clear all ${alerts.length} alerts permanently? This cannot be undone.`)) return
    setClearing(true)
    try {
      await api.clearAlerts()
      onRefresh()
    } catch { alert('Failed to clear alerts') }
    finally { setClearing(false) }
  }

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = filterSeverity === 'all' || alert.severity === filterSeverity
    const matchesSearch   = searchQuery === '' ||
      alert.source_ip.includes(searchQuery) ||
      alert.threat_type.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesSeverity && matchesSearch
  })

  const handleBlockIP = async (ip, e) => {
    e.stopPropagation()
    if (!window.confirm(`Block IP ${ip}? All future traffic from this source will be rejected.`)) return
    setBlockLoading(ip)
    try {
      await api.blockIP(ip, 'Manual block from alerts view')
      onRefresh()
    } catch { alert('Failed to block IP') }
    finally { setBlockLoading(null) }
  }

  const handleDelete = async (id, e) => {
    e.stopPropagation()
    if (!window.confirm('Delete this alert permanently?')) return
    try {
      await api.deleteAlert(id)
      onRefresh()
    } catch { alert('Failed to delete alert') }
  }

  const toggleExpand = (id) => setExpandedId(prev => prev === id ? null : id)

  return (
    <div className="space-y-6">
      {/* Header & Filters */}
      <div className="glass-card p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4 flex-1">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by IP or threat type..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
              />
              {searchQuery && (
                <button onClick={() => setSearchQuery('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white">
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
          <div className="flex items-center gap-3">
            <span className="text-sm text-slate-400">
              Showing <span className="text-white font-medium">{filteredAlerts.length}</span> of{' '}
              <span className="text-white font-medium">{alerts.length}</span>
              <span className="ml-1 text-xs text-slate-600">· click row to explain</span>
            </span>
            <a
              href={`/api/export/csv${filterSeverity !== 'all' ? `?severity=${filterSeverity}` : ''}`}
              download
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 text-xs font-medium transition-colors"
              title="Download alerts as CSV"
            >
              <Download className="w-3.5 h-3.5" /> CSV
            </a>
            <a
              href="/api/export/pdf"
              download
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 border border-indigo-500/30 text-xs font-medium transition-colors"
              title="Download PDF security report"
            >
              <FileText className="w-3.5 h-3.5" /> PDF
            </a>
            {alerts.length > 0 && (
              <button
                onClick={handleClearAll}
                disabled={clearing}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 text-xs font-medium transition-colors disabled:opacity-50"
                title="Clear all alerts"
              >
                <Eraser className="w-3.5 h-3.5" />
                {clearing ? 'Clearing…' : 'Clear All'}
              </button>
            )}
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
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Category</th>
                  <th className="text-left py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Time</th>
                  <th className="text-right py-4 px-6 text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredAlerts.map((alert) => (
                  <>
                    <tr
                      key={alert.id}
                      onClick={() => toggleExpand(alert.id)}
                      className="hover:bg-white/5 transition-colors group cursor-pointer"
                    >
                      <td className="py-4 px-6">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${SEVERITY_STYLES[alert.severity] || 'bg-slate-500/10 text-slate-400'}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-4 px-6">
                        <div>
                          <p className="text-white font-medium text-sm">{alert.threat_type}</p>
                          <p className="text-xs text-slate-500 mt-0.5 truncate max-w-xs">{alert.description}</p>
                        </div>
                      </td>
                      <td className="py-4 px-6">
                        <code className="text-sm text-indigo-400 font-mono bg-indigo-500/10 px-2 py-1 rounded">
                          {alert.source_ip}
                        </code>
                      </td>
                      <td className="py-4 px-6">
                        <div className="text-xs space-y-1">
                          <span className={`inline-block px-2 py-0.5 rounded-full border font-medium ${
                            alert.attack_category === 'DoS'   ? 'text-red-400 bg-red-500/10 border-red-500/30' :
                            alert.attack_category === 'Probe' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' :
                            alert.attack_category === 'R2L'   ? 'text-orange-400 bg-orange-500/10 border-orange-500/30' :
                            alert.attack_category === 'U2R'   ? 'text-pink-400 bg-pink-500/10 border-pink-500/30' :
                            'text-slate-400 bg-slate-500/10 border-slate-500/30'
                          }`}>
                            {alert.attack_category || 'Unknown'}
                          </span>
                          <p className="text-slate-500">ML: {Math.round(alert.ml_score * 100)}%</p>
                        </div>
                      </td>
                      <td className="py-4 px-6 text-sm text-slate-400">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-4 px-6">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={(e) => { e.stopPropagation(); setInvestigatingIP(alert.source_ip) }}
                            className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 border border-indigo-500/30 opacity-0 group-hover:opacity-100 transition-all"
                            title="Investigate IP"
                          >
                            <SearchIcon className="w-4 h-4" />
                          </button>
                          <button
                            onClick={(e) => handleBlockIP(alert.source_ip, e)}
                            disabled={blockLoading === alert.source_ip}
                            className="p-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 opacity-0 group-hover:opacity-100 transition-all disabled:opacity-50"
                            title="Block IP"
                          >
                            <Ban className="w-4 h-4" />
                          </button>
                          <button
                            onClick={(e) => handleDelete(alert.id, e)}
                            className="p-2 rounded-lg bg-slate-700/50 text-slate-400 hover:bg-slate-700 hover:text-white opacity-0 group-hover:opacity-100 transition-all"
                            title="Delete Alert"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                          <span className="text-slate-600 ml-1">
                            {expandedId === alert.id
                              ? <ChevronUp className="w-4 h-4" />
                              : <ChevronDown className="w-4 h-4" />}
                          </span>
                        </div>
                      </td>
                    </tr>

                    {/* Expandable explanation row */}
                    {expandedId === alert.id && (
                      <ExplanationPanel key={`exp-${alert.id}`} alert={alert} />
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {investigatingIP && (
        <IPHistoryModal ip={investigatingIP} onClose={() => setInvestigatingIP(null)} />
      )}
    </div>
  )
}

export default AlertsList
