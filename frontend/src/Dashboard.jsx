import { useState } from 'react'

function Dashboard({ stats, alerts }) {
  if (!stats) return <div className="text-slate-400">Loading...</div>

  // Calculate trend (mock calculation - in real app, compare with previous period)
  const alertTrend = '+12%' // This would be calculated from historical data
  
  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Events"
          value={stats.total_events?.toLocaleString() || 0}
          subtitle="All traffic processed"
          icon="📊"
          trend="+5%"
          color="blue"
        />
        <StatCard
          title="Threats Detected"
          value={stats.total_alerts}
          subtitle={`${((stats.total_alerts / (stats.total_events || 1)) * 100).toFixed(1)}% of traffic`}
          icon="🚨"
          trend={alertTrend}
          color="red"
        />
        <StatCard
          title="Blocked IPs"
          value={stats.blocked_ips_count || 0}
          subtitle="Currently blocked"
          icon="🚫"
          color="orange"
        />
        <StatCard
          title="Last 24h"
          value={stats.alerts_last_24h || 0}
          subtitle="Recent alerts"
          icon="⏰"
          color="green"
        />
      </div>

      {/* Severity Distribution & Top IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-semibold mb-6 flex items-center">
            <span className="mr-2">🎯</span> Severity Distribution
          </h2>
          
          <div className="space-y-4">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(severity => {
              const count = stats.severity_counts[severity] || 0
              const total = stats.total_alerts || 1
              const percentage = ((count / total) * 100).toFixed(1)
              
              return (
                <div key={severity} className="relative">
                  <div className="flex justify-between text-sm mb-1">
                    <span className="font-medium text-slate-300">{severity}</span>
                    <span className="text-slate-400">{count} ({percentage}%)</span>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-3 overflow-hidden">
                    <div 
                      className={`h-full rounded-full transition-all duration-1000 ${getSeverityColor(severity)}`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Top Offending IPs */}
        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-semibold mb-6 flex items-center">
            <span className="mr-2">🔥</span> Top Threat Sources
          </h2>
          
          {stats.top_offending_ips?.length > 0 ? (
            <div className="space-y-3">
              {stats.top_offending_ips.map((item, idx) => (
                <div key={item.ip} className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg border border-slate-700">
                  <div className="flex items-center space-x-3">
                    <span className="text-lg font-bold text-slate-500 w-8">#{idx + 1}</span>
                    <div>
                      <p className="font-mono font-semibold text-red-400">{item.ip}</p>
                      <p className="text-xs text-slate-500">{item.count} alerts</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-16 bg-slate-700 rounded-full h-2">
                      <div 
                        className="bg-red-500 h-2 rounded-full"
                        style={{ width: `${Math.min(100, (item.count / (stats.top_offending_ips[0]?.count || 1)) * 100)}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-center text-slate-500 py-8">No data available</p>
          )}
        </div>
      </div>

      {/* Attack Types & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attack Types */}
        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 lg:col-span-1">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">⚔️</span> Attack Types
          </h2>
          <div className="space-y-3">
            {Object.entries(stats.attack_types || {})
              .sort((a, b) => b[1] - a[1])
              .map(([type, count]) => (
                <div key={type} className="flex items-center justify-between p-3 bg-slate-900/30 rounded-lg">
                  <span className="text-sm text-slate-300">{type}</span>
                  <span className="bg-slate-700 px-3 py-1 rounded-full text-sm font-bold text-white">
                    {count}
                  </span>
                </div>
              ))}
            {Object.keys(stats.attack_types || {}).length === 0 && (
              <p className="text-center py-8 text-slate-500">No attacks detected</p>
            )}
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 lg:col-span-2">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">⚡</span> Recent Activity
          </h2>
          
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {alerts.slice(0, 10).map((alert) => (
              <div
                key={alert.id}
                className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors"
              >
                <div className="flex items-start space-x-3 flex-1">
                  <SeverityDot severity={alert.severity} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <p className="font-medium text-sm truncate">{alert.threat_type}</p>
                      <span className="text-xs text-slate-500">{alert.source_ip}</span>
                    </div>
                    <p className="text-xs text-slate-400 truncate">{alert.description}</p>
                  </div>
                </div>
                <span className="text-xs text-slate-500 whitespace-nowrap ml-4">
                  {new Date(alert.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
            {alerts.length === 0 && (
              <p className="text-center py-8 text-slate-500">Run the demo to generate activity!</p>
            )}
          </div>
        </div>
      </div>

      {/* System Status */}
      <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <span className="mr-2">⚙️</span> System Status
        </h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatusCard title="Event Ingestion" status="active" detail="Processing" />
          <StatusCard title="ML Detection" status="active" detail="Isolation Forest" />
          <StatusCard title="Rule Engine" status="active" detail="5 Rules Active" />
          <StatusCard title="IP Blocking" status={stats.blocked_ips_count > 0 ? "warning" : "active"} 
                     detail={stats.blocked_ips_count > 0 ? `${stats.blocked_ips_count} Blocked` : "Active"} />
        </div>
      </div>
    </div>
  )
}

// Helper Components
function StatCard({ title, value, subtitle, icon, trend, color }) {
  const colors = {
    blue: 'bg-blue-600',
    red: 'bg-red-600',
    orange: 'bg-orange-600',
    green: 'bg-green-600'
  }
  
  return (
    <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 hover:border-slate-600 transition-all hover:transform hover:-translate-y-1">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-slate-400 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold text-white mt-2">{value}</p>
          <p className="text-xs text-slate-500 mt-1">{subtitle}</p>
        </div>
        <span className="text-3xl">{icon}</span>
      </div>
      {trend && (
        <div className="mt-4 flex items-center text-xs">
          <span className={`${trend.startsWith('+') ? 'text-green-400' : 'text-red-400'} font-semibold`}>
            {trend}
          </span>
          <span className="text-slate-500 ml-1">vs last period</span>
        </div>
      )}
    </div>
  )
}

function StatusCard({ title, status, detail }) {
  const statusColors = {
    active: 'bg-green-500',
    warning: 'bg-yellow-500',
    error: 'bg-red-500'
  }
  
  return (
    <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold text-sm text-slate-300">{title}</h3>
        <div className={`w-2 h-2 rounded-full ${statusColors[status]} animate-pulse`} />
      </div>
      <p className="text-xs text-slate-500">{detail}</p>
    </div>
  )
}

function SeverityDot({ severity }) {
  const colors = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-yellow-500',
    LOW: 'bg-green-500'
  }
  return <div className={`w-2 h-2 rounded-full ${colors[severity] || 'bg-slate-500'} mt-2`} />
}

function getSeverityColor(severity) {
  const colors = {
    CRITICAL: 'bg-gradient-to-r from-red-600 to-red-400',
    HIGH: 'bg-gradient-to-r from-orange-600 to-orange-400',
    MEDIUM: 'bg-gradient-to-r from-yellow-600 to-yellow-400',
    LOW: 'bg-gradient-to-r from-green-600 to-green-400'
  }
  return colors[severity] || 'bg-slate-600'
}

export default Dashboard