
import { useCallback, useEffect, useState } from 'react'
import {
  ShieldCheck,
  Activity,
  AlertTriangle,
  CircleCheck,
  RefreshCw,
  Server,
  Clock3,
  ChevronRight,
  ShieldAlert,
  PlusCircle,
  X,
  Search,
  Filter,
} from 'lucide-react'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts'
import './App.css'

const API = 'http://127.0.0.1:8000/api/v1'

const EMPTY_FORM = {
  source_ip: '',
  failed_logins: 0,
  requests_per_minute: 0,
  known_malicious_ip: false,
}

const SEVERITIES = ['ALL', 'HIGH', 'MEDIUM', 'LOW']

function App() {
  const [summary, setSummary] = useState({
    total_incidents: 0,
    severity_breakdown: { LOW: 0, MEDIUM: 0, HIGH: 0 },
  })

  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')

  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('ALL')

  const [showForm, setShowForm] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState('')
  const [result, setResult] = useState(null)
  const [eventForm, setEventForm] = useState(EMPTY_FORM)

  const loadDashboard = useCallback(async (options = {}) => {
    const { initial = false } = options

    if (initial) setLoading(true)
    else setRefreshing(true)

    setError('')

    try {
      const [summaryResponse, incidentsResponse] = await Promise.all([
        fetch(`${API}/incidents/summary`),
        fetch(
          `${API}/incidents?limit=100` +
          `&severity=${encodeURIComponent(severity === 'ALL' ? '' : severity)}` +
          `&search=${encodeURIComponent(search)}`
        ),
      ])

      if (!summaryResponse.ok || !incidentsResponse.ok) {
        throw new Error('Failed to load dashboard data.')
      }

      const summaryData = await summaryResponse.json()
      const incidentsData = await incidentsResponse.json()

      setSummary(summaryData)
      setIncidents(incidentsData.incidents ?? [])
    } catch (err) {
      setError(
        `${err.message} Check that the backend is running at ${API}.`
      )
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [search, severity])

  useEffect(() => {
    loadDashboard({ initial: true })
  }, [loadDashboard])

  function handleSearchSubmit(event) {
    event.preventDefault()
    setSearch(searchInput.trim())
  }

  function clearFilters() {
    setSearchInput('')
    setSearch('')
    setSeverity('ALL')
  }

  function updateField(field, value) {
    setEventForm((previous) => ({
      ...previous,
      [field]: value,
    }))
  }

  async function handleAnalyzeEvent(event) {
    event.preventDefault()
    setSubmitting(true)
    setFormError('')
    setResult(null)

    try {
      const response = await fetch(`${API}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_ip: eventForm.source_ip.trim(),
          failed_logins: Number(eventForm.failed_logins),
          requests_per_minute: Number(eventForm.requests_per_minute),
          known_malicious_ip: eventForm.known_malicious_ip,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        const detail = Array.isArray(data.detail)
          ? data.detail.map((item) => item.msg).join(', ')
          : data.detail

        throw new Error(detail || 'Event analysis failed.')
      }

      setResult(data)
      setEventForm(EMPTY_FORM)

      await loadDashboard()
    } catch (err) {
      setFormError(err.message || 'Unable to analyze this event.')
    } finally {
      setSubmitting(false)
    }
  }

  const chartData = [
    { name: 'HIGH', count: summary.severity_breakdown?.HIGH ?? 0 },
    { name: 'MEDIUM', count: summary.severity_breakdown?.MEDIUM ?? 0 },
    { name: 'LOW', count: summary.severity_breakdown?.LOW ?? 0 },
  ]

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={23} />
          </div>
          <div>
            <h1>AI-CTIR</h1>
            <span>THREAT INTELLIGENCE</span>
          </div>
        </div>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          <a className="nav-item active" href="#overview">
            <Activity size={17} />
            <span>Overview</span>
            <ChevronRight className="nav-chevron" size={15} />
          </a>

          <a className="nav-item" href="#incidents">
            <ShieldAlert size={17} />
            <span>Incidents</span>
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="status-indicator">
            <span className="status-dot" />
            <div>
              <strong>API Connection</strong>
              <small>Local backend</small>
            </div>
          </div>
          <div className="sidebar-version">Prototype v0.1.0</div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div>
            <div className="breadcrumb">Workspace / Overview</div>
            <h2>Security Overview</h2>
            <p className="page-subtitle">
              Monitor and analyze security events across your environment.
            </p>
          </div>

          <div className="heading-actions">
            <button
              className="secondary-button"
              onClick={() => loadDashboard()}
              disabled={refreshing}
            >
              <RefreshCw
                size={15}
                className={refreshing ? 'spin' : ''}
              />
              {refreshing ? 'Refreshing...' : 'Refresh data'}
            </button>

            <button
              className="analyze-button"
              onClick={() => {
                setShowForm((value) => !value)
                setFormError('')
              }}
            >
              {showForm ? <X size={16} /> : <PlusCircle size={16} />}
              {showForm ? 'Close form' : 'Analyze new event'}
            </button>
          </div>
        </header>

        {error && (
          <div className="alert-banner">
            <AlertTriangle size={17} />
            <span>{error}</span>
            <button onClick={() => loadDashboard()} aria-label="Retry">
              Retry
            </button>
          </div>
        )}

        {showForm && (
          <section className="panel event-form-panel">
            <div className="panel-heading">
              <div>
                <h3>Analyze a security event</h3>
                <p>Submit a simulated event to the rule-based detector.</p>
              </div>
            </div>

            <form className="event-form" onSubmit={handleAnalyzeEvent}>
              <div className="form-grid">
                <label className="form-field">
                  Source IP address
                  <input
                    type="text"
                    placeholder="192.0.2.45"
                    value={eventForm.source_ip}
                    onChange={(e) => updateField('source_ip', e.target.value)}
                    required
                  />
                </label>

                <label className="form-field">
                  Failed login attempts
                  <input
                    type="number"
                    min="0"
                    step="1"
                    value={eventForm.failed_logins}
                    onChange={(e) => updateField('failed_logins', e.target.value)}
                    required
                  />
                </label>

                <label className="form-field">
                  Requests per minute
                  <input
                    type="number"
                    min="0"
                    step="1"
                    value={eventForm.requests_per_minute}
                    onChange={(e) =>
                      updateField('requests_per_minute', e.target.value)
                    }
                    required
                  />
                </label>

                <label className="malicious-option">
                  <input
                    type="checkbox"
                    checked={eventForm.known_malicious_ip}
                    onChange={(e) =>
                      updateField('known_malicious_ip', e.target.checked)
                    }
                  />
                  <span>
                    <strong>Flag as known malicious IP</strong>
                    <small>
                      Manual test indicator only. This does not verify the IP
                      against an external threat intelligence feed.
                    </small>
                  </span>
                </label>
              </div>

              <div className="form-actions">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => {
                    setEventForm(EMPTY_FORM)
                    setFormError('')
                    setResult(null)
                  }}
                >
                  Clear fields
                </button>

                <button
                  type="submit"
                  className="analyze-button"
                  disabled={submitting}
                >
                  {submitting ? 'Analyzing...' : 'Analyze event'}
                </button>
              </div>

              {formError && (
                <div className="form-message form-error">
                  <AlertTriangle size={17} />
                  <span>{formError}</span>
                </div>
              )}

              {result && (
                <div className="form-message form-success">
                  <CircleCheck size={18} />
                  <div>
                    <strong>
                      Incident #{result.incident_id} created successfully
                    </strong>
                    <p>
                      Risk score: {result.risk_score}/100 · Severity:{' '}
                      {result.severity}
                    </p>
                    <p>
                      {(result.reasons ?? []).join('; ')}
                    </p>
                  </div>
                </div>
              )}
            </form>
          </section>
        )}

        <section className="metrics-grid">
          <MetricCard
            label="Total Incidents"
            value={summary.total_incidents ?? 0}
            detail="All recorded incidents"
            icon={<Activity size={18} />}
            tone="blue"
          />
          <MetricCard
            label="High Severity"
            value={summary.severity_breakdown?.HIGH ?? 0}
            detail="Requires close attention"
            icon={<AlertTriangle size={18} />}
            tone="red"
          />
          <MetricCard
            label="Medium Severity"
            value={summary.severity_breakdown?.MEDIUM ?? 0}
            detail="Review recommended"
            icon={<ShieldAlert size={18} />}
            tone="amber"
          />
          <MetricCard
            label="Low Severity"
            value={summary.severity_breakdown?.LOW ?? 0}
            detail="Lower risk events"
            icon={<CircleCheck size={18} />}
            tone="green"
          />
        </section>

        <section className="metrics-grid status-metrics-grid">
          <MetricCard
            label="Open Incidents"
            value={summary.status_breakdown?.OPEN ?? 0}
            detail="Awaiting investigation"
            icon={<Clock3 size={18} />}
            tone="amber"
          />
          <MetricCard
            label="Investigating"
            value={summary.status_breakdown?.INVESTIGATING ?? 0}
            detail="Currently under review"
            icon={<ShieldAlert size={18} />}
            tone="blue"
          />
          <MetricCard
            label="Resolved Incidents"
            value={summary.status_breakdown?.RESOLVED ?? 0}
            detail="Marked as resolved"
            icon={<CircleCheck size={18} />}
            tone="green"
          />
        </section>

        <section className="dashboard-grid">
          <div className="panel chart-panel">
            <div className="panel-heading">
              <div>
                <h3>Severity Distribution</h3>
                <p>Recorded incidents grouped by severity.</p>
              </div>
              <span className="panel-icon"><Activity size={17} /></span>
            </div>

            <div className="chart-container">
              {loading ? (
                <div className="empty-state">Loading chart...</div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={chartData}
                    margin={{ top: 10, right: 8, left: -18, bottom: 0 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#263341"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="name"
                      tick={{ fill: '#91a0b0', fontSize: 11 }}
                      axisLine={{ stroke: '#344353' }}
                      tickLine={false}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fill: '#91a0b0', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        background: '#151e28',
                        border: '1px solid #344353',
                        borderRadius: 7,
                        color: '#edf2f7',
                        fontSize: 12,
                      }}
                      cursor={{ fill: '#ffffff08' }}
                    />
                    <Bar
                      dataKey="count"
                      name="Incidents"
                      fill="#5598c9"
                      radius={[4, 4, 0, 0]}
                      maxBarSize={54}
                    />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="panel system-panel">
            <div className="panel-heading">
              <div>
                <h3>System Status</h3>
                <p>Local prototype service overview.</p>
              </div>
              <span className="panel-icon"><Server size={17} /></span>
            </div>

            <div className="system-status-row">
              <div className="system-status-icon"><Server size={17} /></div>
              <div className="system-status-copy">
                <strong>FastAPI Backend</strong>
                <small>127.0.0.1:8000</small>
              </div>
              <span className="status-pill">Local</span>
            </div>

            <div className="system-status-row">
              <div className="system-status-icon"><Activity size={17} /></div>
              <div className="system-status-copy">
                <strong>Detection Engine</strong>
                <small>Rule-based prototype</small>
              </div>
              <span className="status-pill">Active</span>
            </div>

            <div className="system-status-row">
              <div className="system-status-icon"><ShieldCheck size={17} /></div>
              <div className="system-status-copy">
                <strong>Incident Database</strong>
                <small>SQLite storage</small>
              </div>
              <span className="status-pill">Local</span>
            </div>

            <div className="system-note">
              <Clock3 size={15} />
              <span>
                Status labels describe the local prototype configuration; they
                are not independent health checks.
              </span>
            </div>
          </div>
        </section>

        <section className="panel incidents-panel" id="incidents">
          <div className="panel-heading incidents-heading">
            <div>
              <h3>Incident Management</h3>
              <p>Search and filter recorded security incidents.</p>
            </div>
            <span className="result-count">
              {incidents.length} result{incidents.length === 1 ? '' : 's'}
            </span>
          </div>

          <div className="incident-filters">
            <form className="search-form" onSubmit={handleSearchSubmit}>
              <Search size={17} />
              <input
                type="search"
                placeholder="Search incident ID or source IP..."
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                aria-label="Search incident ID or source IP"
              />
              <button type="submit">Search</button>
            </form>

            <label className="severity-select">
              <Filter size={16} />
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                aria-label="Filter by severity"
              >
                {SEVERITIES.map((item) => (
                  <option key={item} value={item}>
                    {item === 'ALL' ? 'All severities' : item}
                  </option>
                ))}
              </select>
            </label>

            <button className="secondary-button clear-filter-button" onClick={clearFilters}>
              Clear filters
            </button>
          </div>

          {loading ? (
            <div className="empty-state">Loading incidents...</div>
          ) : incidents.length === 0 ? (
            <div className="empty-state">
              <Search size={24} />
              <strong>No matching incidents</strong>
              <span>Try another IP address, incident ID, or severity.</span>
              <button className="secondary-button" onClick={clearFilters}>
                Clear filters
              </button>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="incidents-table">
                <thead>
                  <tr>
                    <th>Incident</th>
                    <th>Source IP</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                    <th>Detection Reasons</th>
                    <th>Created At</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((incident) => (
                    <tr key={incident.incident_id}>
                      <td className="incident-id">
                        #{incident.incident_id}
                      </td>
                      <td className="source-ip">{incident.source_ip}</td>
                      <td>
                        <div className="risk-cell">
                          <span>{incident.risk_score}</span>
                          <div className="risk-track">
                            <div
                              className={`risk-fill risk-${incident.severity.toLowerCase()}`}
                              style={{
                                width: `${Math.min(
                                  100,
                                  Math.max(0, incident.risk_score)
                                )}%`,
                              }}
                            />
                          </div>
                        </div>
                      </td>
                      <td>
                        <span
                          className={`severity-badge severity-${incident.severity.toLowerCase()}`}
                        >
                          {incident.severity}
                        </span>
                      </td>
                      <td className="reason-cell">{incident.reasons}</td>
                      <td className="date-cell">
                        {formatDate(incident.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="table-footer">
            Showing up to 100 matching incidents. Search and severity filters
            are applied by the backend.
          </div>
        </section>

        <footer className="app-footer">
          <span>AI-CTIR · Cyber Threat Intelligence Prototype</span>
          <span>Rule-based detection · SQLite</span>
        </footer>
      </main>
    </div>
  )
}

function MetricCard({ label, value, detail, icon, tone }) {
  return (
    <div className="metric-card">
      <div className="metric-top">
        <span className="metric-label">{label}</span>
        <span className={`metric-icon metric-${tone}`}>{icon}</span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  )
}

function formatDate(value) {
  if (!value) return '—'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return value

  return date.toLocaleString()
}

export default App
