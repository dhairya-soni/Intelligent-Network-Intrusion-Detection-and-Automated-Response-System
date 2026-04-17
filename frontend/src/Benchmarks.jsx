import { useState, useEffect } from 'react'
import { api } from './api'
import {
  Trophy, BookOpen, BarChart2, CheckCircle2,
  TrendingUp, Database, Layers, RefreshCw, Info, FlaskConical
} from 'lucide-react'

// ─── helpers ──────────────────────────────────────────────────────────────────
const fmt = (v) => (v != null ? `${Number(v).toFixed(2)}%` : '—')

const BAR_COLORS = {
  accuracy:  'bg-indigo-500',
  precision: 'bg-emerald-500',
  recall:    'bg-amber-500',
  f1:        'bg-purple-500',
}

const CLASS_COLORS = {
  Normal: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  DoS:    'text-red-400    bg-red-500/10    border-red-500/30',
  Probe:  'text-amber-400  bg-amber-500/10  border-amber-500/30',
  R2L:    'text-orange-400 bg-orange-500/10 border-orange-500/30',
  U2R:    'text-pink-400   bg-pink-500/10   border-pink-500/30',
}

function MiniBar({ value, color = 'bg-indigo-500', max = 100 }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100))
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color} transition-all duration-700`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-slate-300 w-14 text-right tabular-nums">
        {fmt(value)}
      </span>
    </div>
  )
}

function MetricCell({ value, best }) {
  const isOurs = best === 'ours'
  const highlight =
    value != null && best != null && Number(value).toFixed(2) === Number(best).toFixed(2)
  return (
    <td
      className={`px-4 py-3 text-sm tabular-nums text-right ${
        highlight
          ? 'text-emerald-400 font-bold'
          : 'text-slate-300'
      }`}
    >
      {fmt(value)}
      {highlight && (
        <span className="ml-1 text-emerald-500 text-xs">★</span>
      )}
    </td>
  )
}

// ─── component ────────────────────────────────────────────────────────────────
export default function Benchmarks() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('comparison')
  // 'kddtest' = official harder split | 'holdout' = same-distribution (matches paper methodology)
  const [evalMode, setEvalMode] = useState('holdout')

  const load = async () => {
    try {
      setLoading(true)
      const res = await api.getBenchmarks()
      setData(res.data)
      setError(null)
    } catch (e) {
      setError('Could not load benchmark data. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  if (loading) return (
    <div className="h-64 flex items-center justify-center text-slate-500">
      <div className="w-10 h-10 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin mr-3" />
      Loading benchmark data...
    </div>
  )

  if (error) return (
    <div className="p-6 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400">
      {error}
    </div>
  )

  const { our_model, published_papers, dataset_info } = data

  // Pick which set of our metrics to show based on the toggle
  const ourAcc  = evalMode === 'holdout' ? our_model.holdout_accuracy  : our_model.accuracy
  const ourPrec = evalMode === 'holdout' ? our_model.holdout_precision : our_model.precision
  const ourRec  = evalMode === 'holdout' ? our_model.holdout_recall    : our_model.recall
  const ourF1   = evalMode === 'holdout' ? our_model.holdout_f1        : our_model.f1

  const ourRow  = { ...our_model, accuracy: ourAcc, precision: ourPrec, recall: ourRec, f1: ourF1, is_ours: true }
  const allRows = [...published_papers, ourRow]

  // Find best value per metric across all rows
  const bestOf = (metric) => {
    const vals = allRows.map(r => r[metric]).filter(v => v != null)
    return vals.length ? Math.max(...vals) : null
  }
  const bestAcc  = bestOf('accuracy')
  const bestPrec = bestOf('precision')
  const bestRec  = bestOf('recall')
  const bestF1   = bestOf('f1')

  const tabs = [
    { id: 'comparison',  label: 'Model Comparison',    icon: BarChart2 },
    { id: 'multiclass',  label: 'Multi-class Results',  icon: Layers },
    { id: 'features',    label: 'Feature Importance',   icon: TrendingUp },
    { id: 'dataset',     label: 'Dataset Info',         icon: Database },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <Trophy className="w-7 h-7 text-amber-400" />
            Research Benchmarks
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            INIDARS vs. published papers on NSL-KDD — same dataset, same test split
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-sm text-slate-300 hover:text-white transition-all"
        >
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Evaluation mode toggle */}
      <div className="flex items-start gap-4 p-4 rounded-xl border border-amber-500/20 bg-amber-500/5">
        <FlaskConical className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" />
        <div className="flex-1">
          <p className="text-sm text-amber-300 font-medium mb-1">Evaluation Methodology</p>
          <p className="text-xs text-slate-400 mb-3">
            Papers reporting 99%+ accuracy use a same-distribution holdout from KDDTrain+.
            The official KDDTest+ set contains novel attack subtypes not present in training, making it intentionally harder.
            Toggle between both to compare fairly.
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setEvalMode('holdout')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                evalMode === 'holdout'
                  ? 'bg-indigo-600 text-white border border-indigo-500'
                  : 'bg-white/5 text-slate-400 border border-white/10 hover:text-slate-200'
              }`}
            >
              Same-Distribution Holdout (matches papers)
            </button>
            <button
              onClick={() => setEvalMode('kddtest')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                evalMode === 'kddtest'
                  ? 'bg-amber-600 text-white border border-amber-500'
                  : 'bg-white/5 text-slate-400 border border-white/10 hover:text-slate-200'
              }`}
            >
              Official KDDTest+ (harder, honest)
            </button>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Binary Accuracy',  value: ourAcc,  best: bestAcc,  icon: TrendingUp,   color: 'text-indigo-400' },
          { label: 'Precision',        value: ourPrec, best: bestPrec, icon: CheckCircle2, color: 'text-emerald-400' },
          { label: 'Recall',           value: ourRec,  best: bestRec,  icon: TrendingUp,   color: 'text-amber-400' },
          { label: 'F1 Score',         value: ourF1,   best: bestF1,   icon: Trophy,       color: 'text-purple-400' },
        ].map(({ label, value, best, icon: Icon, color }) => {
          const isTop = value != null && best != null &&
            Number(value).toFixed(2) === Number(best).toFixed(2)
          return (
            <div
              key={label}
              className={`glass-card p-5 rounded-xl border ${
                isTop ? 'border-emerald-500/40 bg-emerald-500/5' : 'border-white/10'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400">{label}</span>
                {isTop && (
                  <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    #1
                  </span>
                )}
              </div>
              <div className={`text-2xl font-bold ${color}`}>{fmt(value)}</div>
              <div className="text-xs text-slate-500 mt-1">Best in class: {fmt(best)}</div>
            </div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 bg-white/5 rounded-xl border border-white/10 w-fit">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === id
                ? 'bg-indigo-600/30 text-white border border-indigo-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* ── Tab: Comparison Table ── */}
      {activeTab === 'comparison' && (
        <div className="glass-card rounded-xl border border-white/10 overflow-hidden">
          <div className="px-6 py-4 border-b border-white/10 flex items-center gap-3">
            <BookOpen className="w-5 h-5 text-indigo-400" />
            <h3 className="font-semibold text-white">Published Paper Comparison — NSL-KDD</h3>
            <span className="text-xs text-slate-500 ml-auto flex items-center gap-1">
              <Info className="w-3 h-3" /> ★ = best result in column
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10 text-xs text-slate-500 uppercase tracking-wider">
                  <th className="px-4 py-3 text-left">Paper / Method</th>
                  <th className="px-4 py-3 text-left">Year</th>
                  <th className="px-4 py-3 text-right">Accuracy</th>
                  <th className="px-4 py-3 text-right">Precision</th>
                  <th className="px-4 py-3 text-right">Recall</th>
                  <th className="px-4 py-3 text-right">F1</th>
                </tr>
              </thead>
              <tbody>
                {allRows
                  .sort((a, b) => (b.f1 ?? 0) - (a.f1 ?? 0))
                  .map((row) => (
                    <tr
                      key={row.id}
                      className={`border-b border-white/5 transition-colors ${
                        row.is_ours
                          ? 'bg-indigo-500/10 hover:bg-indigo-500/15'
                          : 'hover:bg-white/5'
                      }`}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {row.is_ours && (
                            <span className="px-2 py-0.5 text-xs rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-medium">
                              Ours
                            </span>
                          )}
                          <div>
                            <div className="text-sm font-medium text-white">{row.paper}</div>
                            <div className="text-xs text-slate-500">{row.method}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-400">{row.year}</td>
                      <MetricCell value={row.accuracy}  best={bestAcc} />
                      <MetricCell value={row.precision} best={bestPrec} />
                      <MetricCell value={row.recall}    best={bestRec} />
                      <MetricCell value={row.f1}        best={bestF1} />
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>

          {/* Visual bar comparison */}
          <div className="px-6 py-5 border-t border-white/10">
            <h4 className="text-sm font-medium text-slate-300 mb-4">F1 Score Comparison</h4>
            <div className="space-y-3">
              {allRows
                .filter(r => r.f1 != null)
                .sort((a, b) => b.f1 - a.f1)
                .map((row) => (
                  <div key={row.id} className="flex items-center gap-3">
                    <span
                      className={`text-xs w-44 truncate ${
                        row.is_ours ? 'text-indigo-300 font-semibold' : 'text-slate-400'
                      }`}
                    >
                      {row.paper}
                    </span>
                    <div className="flex-1 h-5 bg-white/5 rounded overflow-hidden">
                      <div
                        className={`h-full rounded transition-all duration-700 flex items-center pl-2 text-xs font-medium ${
                          row.is_ours ? 'bg-indigo-500' : 'bg-slate-600'
                        }`}
                        style={{ width: `${(row.f1 / 100) * 100}%` }}
                      >
                        {row.f1 > 50 && (
                          <span className="text-white/80">{fmt(row.f1)}</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Multi-class Results ── */}
      {activeTab === 'multiclass' && (
        <div className="space-y-4">
          {/* Multi-class summary */}
          {our_model.multiclass_accuracy != null ? (
            <>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                  { label: 'Multi-class Accuracy', value: our_model.multiclass_accuracy, color: 'text-indigo-400' },
                  { label: 'Weighted F1',           value: our_model.multiclass_f1,       color: 'text-purple-400' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="glass-card p-5 rounded-xl border border-white/10">
                    <div className="text-xs text-slate-400 mb-1">{label}</div>
                    <div className={`text-2xl font-bold ${color}`}>{fmt(value)}</div>
                    <div className="text-xs text-slate-500 mt-1">5-class: Normal/DoS/Probe/R2L/U2R</div>
                  </div>
                ))}
              </div>

              {/* Per-class breakdown */}
              {our_model.per_class && Object.keys(our_model.per_class).length > 0 && (
                <div className="glass-card rounded-xl border border-white/10 overflow-hidden">
                  <div className="px-6 py-4 border-b border-white/10 flex items-center gap-3">
                    <Layers className="w-5 h-5 text-purple-400" />
                    <h3 className="font-semibold text-white">Per-Class Metrics</h3>
                  </div>
                  <div className="p-6 space-y-5">
                    {Object.entries(our_model.per_class).map(([cls, m]) => (
                      <div key={cls}>
                        <div className="flex items-center gap-3 mb-2">
                          <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                            CLASS_COLORS[cls] || 'text-slate-300 bg-white/10 border-white/20'
                          }`}>
                            {cls}
                          </span>
                          <span className="text-xs text-slate-500">
                            {m.support?.toLocaleString()} test samples
                          </span>
                        </div>
                        <div className="grid grid-cols-3 gap-4">
                          {[
                            { key: 'precision', label: 'Precision', color: 'bg-emerald-500' },
                            { key: 'recall',    label: 'Recall',    color: 'bg-amber-500' },
                            { key: 'f1',        label: 'F1 Score',  color: 'bg-purple-500' },
                          ].map(({ key, label, color }) => (
                            <div key={key}>
                              <div className="text-xs text-slate-500 mb-1">{label}</div>
                              <MiniBar value={(m[key] ?? 0) * 100} color={color} />
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Individual model comparison */}
              {our_model.individual_models && Object.keys(our_model.individual_models).length > 1 && (
                <div className="glass-card rounded-xl border border-white/10 overflow-hidden">
                  <div className="px-6 py-4 border-b border-white/10">
                    <h3 className="font-semibold text-white">Individual Model vs. Ensemble</h3>
                    <p className="text-xs text-slate-500 mt-1">
                      Each component trained on same data — ensemble outperforms individuals
                    </p>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-white/10 text-xs text-slate-500 uppercase tracking-wider">
                          <th className="px-4 py-3 text-left">Model</th>
                          <th className="px-4 py-3 text-right">Accuracy</th>
                          <th className="px-4 py-3 text-right">F1</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(our_model.individual_models).map(([name, m]) => (
                          <tr key={name} className="border-b border-white/5 hover:bg-white/5">
                            <td className="px-4 py-3 text-sm font-medium text-slate-300 uppercase">
                              {name === 'rf' ? 'Random Forest' : name === 'xgb' ? 'XGBoost' : name === 'lgb' ? 'LightGBM' : name}
                            </td>
                            <td className="px-4 py-3 text-sm text-right text-slate-300 tabular-nums">{fmt(m.accuracy)}</td>
                            <td className="px-4 py-3 text-sm text-right text-slate-300 tabular-nums">{fmt(m.f1)}</td>
                          </tr>
                        ))}
                        <tr className="bg-indigo-500/10 border-b border-white/5">
                          <td className="px-4 py-3 text-sm font-bold text-indigo-300">
                            Ensemble (Soft Voting)
                          </td>
                          <td className="px-4 py-3 text-sm text-right font-bold text-indigo-300 tabular-nums">
                            {fmt(our_model.accuracy)}
                          </td>
                          <td className="px-4 py-3 text-sm text-right font-bold text-indigo-300 tabular-nums">
                            {fmt(our_model.f1)}
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="glass-card p-8 rounded-xl border border-white/10 text-center text-slate-500">
              <Layers className="w-10 h-10 mx-auto mb-3 opacity-40" />
              <p>Multi-class metrics not yet available.</p>
              <p className="text-sm mt-1">Run <code className="text-indigo-400">python train_model.py</code> in the backend folder to generate them.</p>
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Feature Importance ── */}
      {activeTab === 'features' && (() => {
        const globalImp = our_model.per_class
          ? null  // placeholder — comes from model info
          : null

        // Pull feature importance from the benchmarks endpoint
        const modelFeatures = data?.our_model?.feature_importance || null

        return (
          <div className="space-y-4">
            <div className="glass-card rounded-xl border border-white/10 p-6">
              <div className="flex items-center gap-3 mb-2">
                <TrendingUp className="w-5 h-5 text-indigo-400" />
                <h3 className="font-semibold text-white">NSL-KDD Feature Importance (Random Forest)</h3>
              </div>
              <p className="text-xs text-slate-500 mb-6">
                Top 10 features ranked by mean decrease in impurity from the Random Forest component.
                Higher = more critical for distinguishing attack vs normal traffic.
              </p>

              {modelFeatures ? (
                <div className="space-y-3">
                  {modelFeatures.map((f, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <span className="text-xs text-slate-500 w-4 text-right">{i + 1}</span>
                      <span className="text-xs text-slate-300 w-52 truncate font-mono">{f.feature}</span>
                      <div className="flex-1 h-4 bg-white/5 rounded overflow-hidden">
                        <div
                          className="h-full bg-indigo-500 rounded transition-all duration-700"
                          style={{ width: `${(f.importance / modelFeatures[0].importance) * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400 tabular-nums w-16 text-right">
                        {(f.importance * 100).toFixed(2)}%
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-slate-500">
                  <TrendingUp className="w-10 h-10 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">Feature importance will appear here after retraining.</p>
                  <p className="text-xs mt-1">
                    Run <code className="text-indigo-400">python train_model.py</code> to compute it.
                  </p>
                </div>
              )}
            </div>

            {/* What each top NSL-KDD feature means */}
            <div className="glass-card rounded-xl border border-white/10 p-6">
              <h3 className="font-semibold text-white mb-4">Key Feature Descriptions</h3>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {[
                  { name: 'src_bytes',           desc: 'Bytes from source to destination — spikes indicate DDoS or data exfiltration' },
                  { name: 'dst_bytes',           desc: 'Bytes from dest to source — low value with high src_bytes = suspicious' },
                  { name: 'count',               desc: 'Connections to same host in last 2 sec — high = scan or flood' },
                  { name: 'serror_rate',         desc: 'SYN error rate — high = SYN flood (DoS) or port scan' },
                  { name: 'same_srv_rate',       desc: 'Connections to same service — high = service-targeted attack' },
                  { name: 'dst_host_count',      desc: 'Distinct destination hosts — high = worm-like spreading' },
                  { name: 'logged_in',           desc: 'Whether user is logged in — attackers often bypass auth' },
                  { name: 'num_failed_logins',   desc: 'Failed login attempts — direct brute-force indicator' },
                  { name: 'duration',            desc: 'Connection duration — abnormal length signals tunnelling or exfiltration' },
                  { name: 'flag',                desc: 'Network connection state — RST/REJ flags indicate refused connections' },
                ].map(({ name, desc }) => (
                  <div key={name} className="flex gap-3 p-3 rounded-lg bg-white/5 border border-white/5">
                    <code className="text-xs text-indigo-400 font-mono w-40 shrink-0 mt-0.5">{name}</code>
                    <p className="text-xs text-slate-400">{desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )
      })()}

      {/* ── Tab: Dataset Info ── */}
      {activeTab === 'dataset' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="glass-card rounded-xl border border-white/10 p-6 space-y-4">
            <div className="flex items-center gap-3">
              <Database className="w-5 h-5 text-indigo-400" />
              <h3 className="font-semibold text-white">NSL-KDD Dataset</h3>
            </div>
            {[
              { label: 'Source',             value: dataset_info.source },
              { label: 'Year',               value: dataset_info.year },
              { label: 'Training Samples',   value: dataset_info.training_samples },
              { label: 'Test Samples',       value: dataset_info.test_samples },
              { label: 'Features',           value: '41 network traffic features' },
              { label: 'Attack Categories',  value: dataset_info.classes.join(', ') },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between items-start">
                <span className="text-sm text-slate-400">{label}</span>
                <span className="text-sm text-white font-medium text-right max-w-xs">{value}</span>
              </div>
            ))}
          </div>

          <div className="glass-card rounded-xl border border-white/10 p-6 space-y-4">
            <div className="flex items-center gap-3">
              <Info className="w-5 h-5 text-amber-400" />
              <h3 className="font-semibold text-white">Why NSL-KDD?</h3>
            </div>
            <ul className="space-y-3 text-sm text-slate-400">
              {[
                'Removes duplicate records from the original KDD\'99 dataset, preventing bias toward frequent attacks.',
                'Balanced train/test split ensures fair generalisation evaluation.',
                'Standard benchmark used in 500+ peer-reviewed IDS papers — enables direct comparison.',
                'Covers 4 distinct attack families: DoS, Probe, R2L, U2R.',
                'Freely available — reproducible experiments.',
              ].map((point, i) => (
                <li key={i} className="flex gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                  {point}
                </li>
              ))}
            </ul>
          </div>

          {/* Attack type explanations */}
          <div className="lg:col-span-2 glass-card rounded-xl border border-white/10 p-6">
            <h3 className="font-semibold text-white mb-4">Attack Category Descriptions</h3>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { cls: 'DoS',   title: 'Denial of Service', desc: 'Floods target with traffic to exhaust resources. Examples: Neptune, Smurf, Teardrop.' },
                { cls: 'Probe', title: 'Probing / Scanning', desc: 'Surveillance attacks gathering network info. Examples: IPsweep, Portsweep, Nmap.' },
                { cls: 'R2L',   title: 'Remote-to-Local',   desc: 'Unauthorised remote access exploiting vulnerabilities. Examples: FTP_write, Guess_passwd.' },
                { cls: 'U2R',   title: 'User-to-Root',      desc: 'Local privilege escalation to gain root access. Examples: Buffer overflow, Rootkit.' },
              ].map(({ cls, title, desc }) => (
                <div
                  key={cls}
                  className={`p-4 rounded-xl border ${CLASS_COLORS[cls] || 'border-white/10'}`}
                >
                  <div className="font-semibold text-sm mb-1">{cls}</div>
                  <div className="text-xs font-medium mb-2 text-white/80">{title}</div>
                  <div className="text-xs text-slate-400">{desc}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
