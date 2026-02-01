import { useState } from 'react'
import { 
  Shield, 
  AlertTriangle, 
  Ban, 
  Clock, 
  TrendingUp,
  Server,
  Activity
} from 'lucide-react'

function Dashboard({ stats, alerts }) {
  if (!stats) return null

  const severityData = [
    { label: 'Critical', count: stats.severity_counts?.CRITICAL || 0, color: 'bg-red-500', width: 'w-red' },
    { label: 'High', count: stats.severity_counts?.HIGH || 0, color: 'bg-orange-500', width: 'w-orange' },
    { label: 'Medium', count: stats.severity_counts?.MEDIUM || 0, color: 'bg-yellow-500', width: 'w-yellow' },
    { label: 'Low', count: stats.severity_counts?.LOW || 0, color: 'bg-green-500', width: 'w-green' }
  ]

  const total = stats.total_alerts || 1

  return (
    <div className="space-y-6">
      {/* Top Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Events"
          value={stats.total_events?.toLocaleString() || 0}
          subtitle="Events processed"
          icon={Server}
          trend="+5%"
          color="from-blue-500 to-blue-600"
        />
        <StatCard
          title="Threats Detected"
          value={stats.total_alerts}
          subtitle={`${((stats.total_alerts / (stats.total_events || 1)) * 100).toFixed(1)}% threat rate`}
          icon={AlertTriangle}
          trend="+12%"
          color="from-red-500 to-red-600"
        />
        <StatCard
          title="Blocked IPs"
          value={stats.blocked_ips_count || 0}
          subtitle="Active blocks"
          icon={Ban}
          color="from-amber-500 to-amber-600"
        />
        <StatCard
          title="Last 24 Hours"
          value={stats.alerts_last_24h || 0}
          subtitle="Recent alerts"
          icon={Clock}
          color="from-emerald-500 to-emerald-600"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="lg:col-span-1 glass-card p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-white">Threat Severity</h3>
            <span className="text-xs text-slate-400 bg-white/5 px-3 py-1 rounded-full">Live</span>
          </div>
          
          <div className="space-y-4">
            {severityData.map((item) => {
              const percentage = ((item.count / total) * 100).toFixed(1)
              return (
                <div key={item.label}>
                  <div className="flex justify-between text-sm mb-2">
                    <span className="text-slate-300 font-medium">{item.label}</span>
                    <span className="text-slate-400">{item.count} ({percentage}%)</span>
                  </div>
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                    <div 
                      className={`h-full ${item.color} transition-all duration-500`}
                      style={{ width: `${percentage}%` }}
                    ></div>
                  </div>
                </div>
              )
            })}
          </div>

          <div className="mt-6 pt-6 border-t border-white/10">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Total Alerts</span>
              <span className="text-white font-bold text-lg">{stats.total_alerts}</span>
            </div>
          </div>
        </div>

        {/* Top Attackers */}
        <div className="lg:col-span-2 glass-card p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-white">Top Threat Sources</h3>
            <button className="text-xs text-indigo-400 hover:text-indigo-300 font-medium">View All</button>
          </div>

          {stats.top_offending_ips?.length > 0 ? (
            <div className="space-y-3">
              {stats.top_offending_ips.map((item, idx) => (
                <div 
                  key={item.ip} 
                  className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-white/10 hover:border-indigo-500/30 transition-colors group"
                >
                  <div className="flex items-center gap-4">
                    <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 flex items-center justify-center text-sm font-bold text-indigo-400">
                      #{idx + 1}
                    </div>
                    <div>
                      <p className="font-mono text-white font-medium">{item.ip}</p>
                      <p className="text-xs text-slate-400">{item.count} alerts detected</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-4">
                    <div className="w-32 h-2 bg-white/10 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-red-500 to-orange-500"
                        style={{ width: `${Math.min(100, (item.count / (stats.top_offending_ips[0]?.count || 1)) * 100)}%` }}
                      ></div>
                    </div>
                    <span className="text-sm font-bold text-white w-8 text-right">{item.count}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center text-slate-500">
              No threat data available
            </div>
          )}
        </div>
      </div>

      {/* Model Performance */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-indigo-400" />
            <h3 className="text-lg font-semibold text-white">ML Model Performance</h3>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
            <span className="text-xs text-emerald-400 font-medium">NSL-KDD Trained</span>
          </div>
        </div>

        {stats.model_info?.accuracy && stats.model_info.accuracy !== 'N/A (Demo Mode)' ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <MetricBox label="Accuracy" value={stats.model_info.accuracy} icon={TrendingUp} />
            <MetricBox label="Precision" value={stats.model_info.precision} icon={Shield} />
            <MetricBox label="Recall" value={stats.model_info.recall} icon={Activity} />
            <MetricBox label="F1-Score" value={stats.model_info.f1} icon={TrendingUp} />
          </div>
        ) : (
          <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-sm">
            Training data not detected. Run train_model.py with NSL-KDD dataset to enable metrics.
          </div>
        )}

        <div className="mt-6 pt-6 border-t border-white/10 flex items-center justify-between text-sm text-slate-400">
          <div className="flex items-center gap-6">
            <span>Training Samples: <span className="text-slate-200 font-medium">{stats.model_info?.training_samples || 'N/A'}</span></span>
            <span>Features: <span className="text-slate-200 font-medium">{stats.model_info?.features || '10 basic'}</span></span>
          </div>
          <span className="text-slate-500">Model: Isolation Forest + Rule Engine</span>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white">Recent Activity</h3>
          <span className="text-xs text-slate-400">Last 10 alerts</span>
        </div>

        <div className="space-y-2">
          {alerts.slice(0, 10).map((alert) => (
            <div
              key={alert.id}
              className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 transition-colors"
            >
              <div className="flex items-center gap-4">
                <SeverityIndicator severity={alert.severity} />
                <div>
                  <p className="text-white font-medium text-sm">{alert.threat_type}</p>
                  <p className="text-xs text-slate-400">{alert.source_ip} • {alert.protocol}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-xs text-slate-400">{new Date(alert.timestamp).toLocaleTimeString()}</p>
                <p className="text-xs text-slate-500">Score: {(alert.ml_score * 100).toFixed(0)}%</p>
              </div>
            </div>
          ))}
          {alerts.length === 0 && (
            <div className="h-32 flex items-center justify-center text-slate-500 text-sm">
              No recent activity. Run demo to generate events.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, subtitle, icon: Icon, trend, color }) {
  return (
    <div className="glass-card p-6 hover:border-indigo-500/30 transition-all group">
      <div className="flex items-start justify-between mb-4">
        <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${color} flex items-center justify-center shadow-lg`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
        {trend && (
          <span className="text-xs font-medium text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded-full border border-emerald-500/20">
            {trend}
          </span>
        )}
      </div>
      
      <div>
        <p className="text-2xl font-bold text-white mb-1">{value}</p>
        <p className="text-sm text-slate-400 mb-1">{title}</p>
        <p className="text-xs text-slate-500">{subtitle}</p>
      </div>
    </div>
  )
}

function MetricBox({ label, value, icon: Icon }) {
  return (
    <div className="text-center p-4 rounded-xl bg-white/5 border border-white/10">
      <div className="w-10 h-10 mx-auto mb-3 rounded-lg bg-indigo-500/10 flex items-center justify-center">
        <Icon className="w-5 h-5 text-indigo-400" />
      </div>
      <p className="text-2xl font-bold text-white mb-1">{value || '0%'}</p>
      <p className="text-xs text-slate-400 uppercase tracking-wider">{label}</p>
    </div>
  )
}

function SeverityIndicator({ severity }) {
  const colors = {
    CRITICAL: 'bg-red-500 shadow-red-500/50',
    HIGH: 'bg-orange-500 shadow-orange-500/50',
    MEDIUM: 'bg-yellow-500 shadow-yellow-500/50',
    LOW: 'bg-green-500 shadow-green-500/50'
  }
  
  return (
    <div className={`w-2 h-8 rounded-full ${colors[severity] || 'bg-slate-500'} shadow-lg`}></div>
  )
}

export default Dashboard