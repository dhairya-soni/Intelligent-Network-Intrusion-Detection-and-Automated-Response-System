import { useState } from 'react'

function AlertsList({ alerts, onRefresh }) {
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [filterSeverity, setFilterSeverity] = useState('all')

  const filteredAlerts = filterSeverity === 'all'
    ? alerts
    : alerts.filter(a => a.severity === filterSeverity)

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <span className="text-sm text-slate-400">Filter by severity:</span>
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
            <p className="text-sm text-slate-500 mt-2">Run the demo to generate some attacks!</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                    Threat Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                    Destination
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                    ML Score
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="hover:bg-slate-700/50 transition-colors cursor-pointer"
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-300">
                      {alert.threat_type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-slate-400">
                      {alert.source_ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-slate-400">
                      {alert.dest_ip}:{alert.dest_port}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <div className="flex items-center space-x-2">
                        <div className="w-16 bg-slate-700 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full ${getScoreColor(alert.ml_score)}`}
                            style={{ width: `${alert.ml_score * 100}%` }}
                          />
                        </div>
                        <span className="text-slate-400">{(alert.ml_score * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedAlert(alert)
                        }}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        View Details →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </div>
  )
}

function SeverityBadge({ severity }) {
  const colors = {
    CRITICAL: 'bg-red-600 text-white',
    HIGH: 'bg-orange-600 text-white',
    MEDIUM: 'bg-yellow-600 text-white',
    LOW: 'bg-green-600 text-white'
  }
  
  return (
    <span className={`px-2 py-1 rounded text-xs font-semibold ${colors[severity] || 'bg-gray-600'}`}>
      {severity}
    </span>
  )
}

function getScoreColor(score) {
  if (score > 0.85) return 'bg-red-500'
  if (score > 0.7) return 'bg-orange-500'
  if (score > 0.5) return 'bg-yellow-500'
  return 'bg-green-500'
}

function AlertDetailModal({ alert, onClose }) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-800 rounded-lg border border-slate-700 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-slate-700 flex items-center justify-between sticky top-0 bg-slate-800">
          <h2 className="text-xl font-semibold">Alert Details</h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white text-2xl"
          >
            ×
          </button>
        </div>
        
        <div className="p-6 space-y-6">
          {/* Header Info */}
          <div className="flex items-center justify-between">
            <SeverityBadge severity={alert.severity} />
            <span className="text-sm text-slate-400">
              {new Date(alert.timestamp).toLocaleString()}
            </span>
          </div>

          {/* Threat Type */}
          <div>
            <h3 className="text-lg font-semibold mb-2">{alert.threat_type}</h3>
            <p className="text-slate-300">{alert.description}</p>
          </div>

          {/* Detection Info */}
          <div className="grid grid-cols-2 gap-4">
            <InfoCard title="ML Anomaly Score" value={`${(alert.ml_score * 100).toFixed(1)}%`} />
            <InfoCard title="Confidence" value={`${alert.confidence}%`} />
            <InfoCard title="Rule Matched" value={alert.rule_matched ? 'Yes' : 'No'} />
            <InfoCard title="Protocol" value={alert.protocol.toUpperCase()} />
          </div>

          {/* Network Info */}
          <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
            <h4 className="font-semibold mb-3">Network Information</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Source IP:</span>
                <span className="font-mono">{alert.source_ip}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Destination IP:</span>
                <span className="font-mono">{alert.dest_ip}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Destination Port:</span>
                <span className="font-mono">{alert.dest_port}</span>
              </div>
            </div>
          </div>

          {/* Recommendation */}
          <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
            <h4 className="font-semibold mb-2 text-blue-300">Recommended Action</h4>
            <p className="text-sm text-slate-300">{alert.recommendation}</p>
          </div>

          {/* Actions */}
          <div className="flex space-x-3">
            <button className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
              Block IP
            </button>
            <button className="flex-1 bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg transition-colors">
              Investigate
            </button>
            <button
              onClick={onClose}
              className="px-6 bg-slate-700 hover:bg-slate-600 text-white py-2 rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function InfoCard({ title, value }) {
  return (
    <div className="bg-slate-700/50 rounded-lg p-3 border border-slate-600">
      <p className="text-xs text-slate-400 mb-1">{title}</p>
      <p className="text-lg font-semibold">{value}</p>
    </div>
  )
}

export default AlertsList
