
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
  Eye,
  Loader2,
  Hash,
  Globe,
  Gauge,
  FileText,
  Info,
  Sparkles,
  User,
  UserCheck,
  MessageSquare,
  Send,
  Ban,
  CheckCircle,
  RotateCcw,
  Lock,
  LogIn,
  LogOut,
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

function resolveApiUrl() {
  const envUrl = (import.meta.env?.VITE_API_BASE_URL || '').trim()
  if (envUrl) {
    return envUrl.endsWith('/api/v1') ? envUrl : `${envUrl.replace(/\/+$/, '')}/api/v1`
  }
  // In production builds, default to same-origin reverse-proxy path (/api/v1).
  // This guarantees remote clients connect to the host serving the web app
  // rather than attempting to connect to their own local computer.
  if (import.meta.env?.PROD) {
    return '/api/v1'
  }
  // Local development fallback
  return 'http://127.0.0.1:8000/api/v1'
}

const API = resolveApiUrl()

const DEFAULT_FEATURES = JSON.stringify(
  { 'Flow Duration': 100.0, 'Total Fwd Packets': 5.0 },
  null,
  2
)

const EMPTY_FORM = {
  source_ip: '',
  destination_ip: '',
  destination_port: '',
  protocol: '',
  features_json: DEFAULT_FEATURES,
}

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const STATUS_OPTIONS = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED']

const CONNECTOR_SAMPLES = {
  NGINX_ACCESS: '198.51.100.25 - - [11/Nov/2026:14:32:10 +0000] "GET /admin/config.php HTTP/1.1" 404 342 "-" "Mozilla/5.0"',
  SURICATA_EVE: JSON.stringify({
    timestamp: "2026-11-11T14:32:10.000Z",
    event_type: "alert",
    src_ip: "198.51.100.45",
    src_port: 54321,
    dest_ip: "10.0.0.1",
    dest_port: 80,
    proto: "TCP",
    alert: {
      action: "allowed",
      gid: 1,
      signature_id: 2001219,
      rev: 2,
      signature: "ET SCAN Potential SSH Scan OUTBOUND",
      category: "Attempted Information Leak",
      severity: 2
    }
  }, null, 2),
  SYSLOG_AUTH: 'Nov 11 14:32:10 soc-gateway sshd[2412]: Failed password for invalid user admin from 198.51.100.77 port 48212 ssh2'
}

function getIncidentSourceBadge(incident) {
  if (!incident) return { label: 'ML Flow', class: 'source-netflow' }
  const reasons = incident.reasons || ''
  if (reasons.includes('[NGINX_ACCESS]')) {
    return { label: 'Nginx Access', class: 'source-nginx' }
  }
  if (reasons.includes('[SURICATA_EVE]')) {
    return { label: 'Suricata NIDS', class: 'source-suricata' }
  }
  if (reasons.includes('[SYSLOG_AUTH]')) {
    return { label: 'Syslog Auth', class: 'source-syslog' }
  }
  return { label: 'ML Flow', class: 'source-netflow' }
}

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
  const [featuresParseError, setFeaturesParseError] = useState('')

  // Incident detail drawer state
  const [selectedIncidentId, setSelectedIncidentId] = useState(null)
  const [incidentDetail, setIncidentDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')

  // Milestone 7 & Phase 3B: Secure Browser Sessions (HttpOnly Cookie + In-Memory CSRF Synchronizer)
  const [authUser, setAuthUser] = useState(null)
  const [csrfToken, setCsrfToken] = useState('')
  const [authChecking, setAuthChecking] = useState(true)

  // Explicit Authentication Modal / Screen State
  const [loginUsername, setLoginUsername] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginLoading, setLoginLoading] = useState(false)
  const [loginError, setLoginError] = useState('')

  // Universal Ingestion Connector State
  const [ingestMode, setIngestMode] = useState('connectors')
  const [connectorSource, setConnectorSource] = useState('NGINX_ACCESS')
  const [rawPayload, setRawPayload] = useState(CONNECTOR_SAMPLES.NGINX_ACCESS)
  const [rawSubmitting, setRawSubmitting] = useState(false)
  const [rawResult, setRawResult] = useState(null)
  const [rawError, setRawError] = useState('')

  // Hydrate browser session and in-memory CSRF token on initial mount
  useEffect(() => {
    let isMounted = true
    async function checkSession() {
      try {
        const res = await fetch(`${API}/auth/session/me`, {
          credentials: 'include',
        })
        if (res.ok) {
          const data = await res.json()
          if (isMounted) {
            setAuthUser(data.user)
            setCsrfToken(data.csrf_token || '')
          }
        } else {
          if (isMounted) {
            setAuthUser(null)
            setCsrfToken('')
          }
        }
      } catch {
        if (isMounted) {
          setAuthUser(null)
          setCsrfToken('')
        }
      } finally {
        if (isMounted) {
          setAuthChecking(false)
        }
      }
    }
    checkSession()
    return () => {
      isMounted = false
    }
  }, [])

  async function handleLogin(e) {
    if (e) e.preventDefault()
    if (!loginUsername.trim() || !loginPassword) {
      setLoginError('Username and password are required.')
      return
    }
    setLoginLoading(true)
    setLoginError('')
    try {
      const res = await fetch(`${API}/auth/session/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          username: loginUsername.trim(),
          password: loginPassword,
        }),
      })
      const data = await res.json()
      if (!res.ok) {
        throw new Error(data?.detail || 'Authentication failed.')
      }
      setAuthUser(data.user)
      setCsrfToken(data.csrf_token || '')
      setLoginPassword('')
      setLoginError('')
    } catch (err) {
      setLoginError(err.message || 'Unable to connect to authentication server.')
    } finally {
      setLoginLoading(false)
    }
  }

  async function handleLogout() {
    try {
      if (csrfToken) {
        await fetch(`${API}/auth/session/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-SENTRIX-CSRF': csrfToken,
          },
          credentials: 'include',
        })
      }
    } catch {
      // Ignore logout transport errors, always clear in-memory state
    } finally {
      setAuthUser(null)
      setCsrfToken('')
      setLoginPassword('')
      setLoginError('')
    }
  }

  const loadDashboard = useCallback(async (options = {}) => {
    const { initial = false } = options

    if (initial) setLoading(true)
    else setRefreshing(true)

    setError('')

    try {
      const [summaryResponse, incidentsResponse] = await Promise.all([
        fetch(`${API}/incidents/summary`, { credentials: 'include' }),
        fetch(
          `${API}/incidents?limit=100` +
          `&severity=${encodeURIComponent(severity === 'ALL' ? '' : severity)}` +
          `&search=${encodeURIComponent(search)}`,
          { credentials: 'include' }
        ),
      ])

      if (incidentsResponse.status === 401) {
        await handleLogout()
        throw new Error('Session expired or unauthorized. Please sign in.')
      }

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
    if (authUser) {
      loadDashboard({ initial: true })
    }
  }, [loadDashboard, authUser])

  async function openIncidentDetail(incidentId) {
    setSelectedIncidentId(incidentId)
    setIncidentDetail(null)
    setDetailError('')
    setDetailLoading(true)

    try {
      const response = await fetch(`${API}/incidents/${incidentId}`, {
        credentials: 'include',
      })
      if (!response.ok) {
        if (response.status === 401) {
          await handleLogout()
          throw new Error('Session expired or unauthorized. Please sign in.')
        }
        throw new Error(
          response.status === 404
            ? `Incident #${incidentId} not found.`
            : `Failed to load incident details (HTTP ${response.status}).`
        )
      }
      const data = await response.json()
      setIncidentDetail(data)
    } catch (err) {
      setDetailError(err.message || 'Unable to load incident details.')
    } finally {
      setDetailLoading(false)
    }
  }

  function closeIncidentDetail() {
    setSelectedIncidentId(null)
    setIncidentDetail(null)
    setDetailError('')
    setDetailLoading(false)
  }

  function handleIncidentStatusUpdated(updatedIncident) {
    setIncidentDetail(updatedIncident)
    const updatedId = updatedIncident.incident_id ?? updatedIncident.id
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.incident_id === updatedId ? { ...inc, ...updatedIncident } : inc
      )
    )
    loadDashboard()
  }

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
    if (field === 'features_json') setFeaturesParseError('')
  }

  async function handleAnalyzeEvent(e) {
    e.preventDefault()
    setFormError('')
    setResult(null)
    setFeaturesParseError('')

    let features
    try {
      features = JSON.parse(eventForm.features_json)
      if (typeof features !== 'object' || Array.isArray(features) || features === null) {
        throw new Error('Features must be a JSON object.')
      }
    } catch (err) {
      setFeaturesParseError(err.message || 'Invalid JSON in features field.')
      return
    }

    const payload = { features }
    if (eventForm.source_ip.trim()) payload.source_ip = eventForm.source_ip.trim()
    if (eventForm.destination_ip.trim()) payload.destination_ip = eventForm.destination_ip.trim()
    if (eventForm.destination_port.trim()) payload.destination_port = Number(eventForm.destination_port)
    if (eventForm.protocol.trim()) payload.protocol = eventForm.protocol.trim()

    setSubmitting(true)
    try {
      const response = await fetch(`${API}/simulation/event`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
        body: JSON.stringify(payload),
      })

      const data = await response.json()

      if (!response.ok) {
        if (response.status === 401) {
          await handleLogout()
          throw new Error('Session expired. Please sign in.')
        }
        const detail = Array.isArray(data.detail)
          ? data.detail.map((item) => item.msg).join(', ')
          : (typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail))
        throw new Error(detail || 'Event submission failed.')
      }

      setResult(data)
      setEventForm(EMPTY_FORM)
      await loadDashboard()
    } catch (err) {
      setFormError(err.message || 'Unable to submit this event.')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleIngestRaw(e) {
    e.preventDefault()
    setRawError('')
    setRawResult(null)

    if (!rawPayload.trim()) {
      setRawError('Please enter a log line or payload.')
      return
    }

    let payloadToSend = rawPayload.trim()
    if (connectorSource === 'SURICATA_EVE') {
      try {
        payloadToSend = JSON.parse(rawPayload.trim())
      } catch (err) {
        setRawError('Invalid JSON format for Suricata EVE alert.')
        return
      }
    }

    setRawSubmitting(true)
    try {
      const response = await fetch(`${API}/simulation/raw`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
        body: JSON.stringify({
          source_type: connectorSource,
          raw_payload: payloadToSend,
        }),
      })

      const data = await response.json()
      if (!response.ok) {
        if (response.status === 401) {
          await handleLogout()
          throw new Error('Session expired. Please sign in.')
        }
        throw new Error(data?.detail || 'Raw telemetry ingestion failed.')
      }

      setRawResult(data)
      await loadDashboard()
    } catch (err) {
      setRawError(err.message || 'Unable to ingest raw telemetry.')
    } finally {
      setRawSubmitting(false)
    }
  }

  const chartData = [
    { name: 'CRITICAL', count: summary.severity_breakdown?.CRITICAL ?? 0 },
    { name: 'HIGH', count: summary.severity_breakdown?.HIGH ?? 0 },
    { name: 'MEDIUM', count: summary.severity_breakdown?.MEDIUM ?? 0 },
    { name: 'LOW', count: summary.severity_breakdown?.LOW ?? 0 },
  ]

  if (authChecking) {
    return (
      <div className="login-screen-container">
        <div className="login-card" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '260px' }}>
          <Loader2 className="animate-spin" size={32} style={{ color: '#00ffff' }} />
        </div>
      </div>
    )
  }

  if (!authUser) {
    return (
      <div className="login-screen-container">
        <div className="login-card">
          <div className="login-brand">
            <div className="brand-mark">
              <ShieldCheck size={26} />
            </div>
            <div className="login-brand-text">
              <h2>SENTRIX</h2>
              <span>AUTONOMOUS THREAT DEFENSE</span>
            </div>
          </div>

          <div className="login-header">
            <h3>SecOps Portal Authentication</h3>
            <p>
              Sign in with your verified SecOps credentials to access threat telemetry, incident triage, and automated containment actions.
            </p>
          </div>

          {loginError && (
            <div className="alert-banner login-error-banner">
              <AlertTriangle size={16} />
              <span>{loginError}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="login-form">
            <div className="login-field">
              <label htmlFor="sentrix-username">Username</label>
              <div className="login-input-wrapper">
                <User size={15} className="login-icon" />
                <input
                  id="sentrix-username"
                  type="text"
                  placeholder="e.g. admin or analyst"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  disabled={loginLoading}
                  autoComplete="username"
                  required
                />
              </div>
            </div>

            <div className="login-field">
              <label htmlFor="sentrix-password">Password</label>
              <div className="login-input-wrapper">
                <Lock size={15} className="login-icon" />
                <input
                  id="sentrix-password"
                  type="password"
                  placeholder="Enter SOC account password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  disabled={loginLoading}
                  autoComplete="current-password"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              className="analyze-button login-btn"
              disabled={loginLoading}
            >
              {loginLoading ? (
                <>
                  <Loader2 size={16} className="spin" />
                  <span>Verifying Credentials...</span>
                </>
              ) : (
                <>
                  <LogIn size={16} />
                  <span>Sign In to SENTRIX</span>
                </>
              )}
            </button>
          </form>

          <div className="login-footer">
            <small>SENTRIX AI-Powered Autonomous Threat Defense &bull; v0.2.0</small>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={23} />
          </div>
          <div>
            <h1>SENTRIX</h1>
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
          <div className="sidebar-version">v0.2.0</div>
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
            <div className="auth-user-badge">
              <span className="auth-user-icon"><User size={13} /></span>
              <span className="auth-username">{authUser?.username || 'SecOps User'}</span>
              <span className={`role-badge role-badge-${(authUser?.role || 'analyst').toLowerCase()}`}>
                {(authUser?.role || 'analyst').toUpperCase()}
              </span>
              <button
                type="button"
                className="switch-role-btn"
                onClick={handleLogout}
                title="Sign out of current SecOps session"
              >
                <LogOut size={11} />
                <span>Sign Out</span>
              </button>
            </div>

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
                setFeaturesParseError('')
              }}
            >
              {showForm ? <X size={16} /> : <PlusCircle size={16} />}
              {showForm ? 'Close form' : 'Submit new event'}
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
            <div className="panel-heading telemetry-panel-heading">
              <div>
                <h3>Telemetry Ingestion Hub</h3>
                <p>
                  Ingest real-world enterprise telemetry (Nginx, Suricata, Syslog) or direct 78-feature network flow.
                </p>
              </div>
              <div className="telemetry-mode-switch">
                <button
                  type="button"
                  className={`telemetry-mode-btn ${ingestMode === 'connectors' ? 'active' : ''}`}
                  onClick={() => {
                    setIngestMode('connectors')
                    setFormError('')
                    setRawError('')
                  }}
                >
                  Universal Log Shipper (Nginx/Suricata/Syslog)
                </button>
                <button
                  type="button"
                  className={`telemetry-mode-btn ${ingestMode === 'network_flow' ? 'active' : ''}`}
                  onClick={() => {
                    setIngestMode('network_flow')
                    setFormError('')
                    setRawError('')
                  }}
                >
                  Network Flow (78-Feature ML)
                </button>
              </div>
            </div>

            {ingestMode === 'connectors' ? (
              <form className="event-form connector-ingest-form" onSubmit={handleIngestRaw}>
                <div className="connector-select-row">
                  <div className="connector-pills-group">
                    <button
                      type="button"
                      className={`connector-format-pill ${connectorSource === 'NGINX_ACCESS' ? 'active' : ''}`}
                      onClick={() => {
                        setConnectorSource('NGINX_ACCESS')
                        setRawPayload(CONNECTOR_SAMPLES.NGINX_ACCESS)
                        setRawError('')
                        setRawResult(null)
                      }}
                    >
                      Nginx / Web Access
                    </button>
                    <button
                      type="button"
                      className={`connector-format-pill ${connectorSource === 'SURICATA_EVE' ? 'active' : ''}`}
                      onClick={() => {
                        setConnectorSource('SURICATA_EVE')
                        setRawPayload(CONNECTOR_SAMPLES.SURICATA_EVE)
                        setRawError('')
                        setRawResult(null)
                      }}
                    >
                      Suricata EVE JSON
                    </button>
                    <button
                      type="button"
                      className={`connector-format-pill ${connectorSource === 'SYSLOG_AUTH' ? 'active' : ''}`}
                      onClick={() => {
                        setConnectorSource('SYSLOG_AUTH')
                        setRawPayload(CONNECTOR_SAMPLES.SYSLOG_AUTH)
                        setRawError('')
                        setRawResult(null)
                      }}
                    >
                      Linux Auth / SSH Syslog
                    </button>
                  </div>

                  <button
                    type="button"
                    className="load-sample-btn"
                    onClick={() => {
                      setRawPayload(CONNECTOR_SAMPLES[connectorSource])
                      setRawError('')
                    }}
                  >
                    Load Sample Log
                  </button>
                </div>

                <div className="form-field raw-log-field">
                  <label className="features-hint">
                    {connectorSource === 'NGINX_ACCESS' && 'Paste Nginx/Apache Combined or Common access log line:'}
                    {connectorSource === 'SURICATA_EVE' && 'Paste Suricata or Snort EVE alert JSON record:'}
                    {connectorSource === 'SYSLOG_AUTH' && 'Paste Linux syslog auth.log line (e.g. SSH Failed password):'}
                  </label>
                  <textarea
                    className="raw-log-textarea"
                    rows={5}
                    spellCheck={false}
                    value={rawPayload}
                    onChange={(e) => setRawPayload(e.target.value)}
                    required
                  />
                </div>

                <div className="form-actions">
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => {
                      setRawPayload('')
                      setRawError('')
                      setRawResult(null)
                    }}
                  >
                    Clear log
                  </button>
                  <button
                    type="submit"
                    className="analyze-button"
                    disabled={rawSubmitting}
                  >
                    {rawSubmitting ? 'Parsing & Ingesting...' : 'Ingest & Normalize Log'}
                  </button>
                </div>

                {rawError && (
                  <div className="form-message form-error">
                    <AlertTriangle size={17} />
                    <span>{rawError}</span>
                  </div>
                )}

                {rawResult && (
                  <div className={`form-message ${rawResult.incident_created ? 'form-error' : 'form-success'}`}>
                    {rawResult.incident_created ? <AlertTriangle size={17} /> : <CircleCheck size={18} />}
                    <div className="raw-result-content">
                      <strong>
                        Telemetry normalized successfully: {rawResult.normalized_data?.event_type}
                      </strong>
                      <p>
                        Source IP: <code>{rawResult.normalized_data?.source_ip || 'N/A'}</code>
                        {' · '}
                        Port: {rawResult.normalized_data?.destination_port || 'N/A'} ({rawResult.normalized_data?.protocol || 'TCP'})
                        {' · '}
                        Reason: {rawResult.normalized_data?.detection_reason}
                      </p>
                      {rawResult.incident_created && rawResult.incident_id && (
                        <p className="incident-created-alert">
                          ⚡ Incident #{rawResult.incident_id} created and correlated to SOC dashboard.
                        </p>
                      )}
                      {!rawResult.incident_created && rawResult.incident_id && (
                        <p className="incident-created-alert">
                          ⚡ Correlated into active Incident #{rawResult.incident_id}.
                        </p>
                      )}
                      {!rawResult.incident_created && !rawResult.incident_id && (
                        <p>Event persisted. No threat thresholds triggered.</p>
                      )}
                    </div>
                  </div>
                )}
              </form>
            ) : (
              <form className="event-form" onSubmit={handleAnalyzeEvent}>
                <div className="form-grid">
                  <label className="form-field">
                    Source IP address
                    <input
                      type="text"
                      placeholder="192.0.2.45"
                      value={eventForm.source_ip}
                      onChange={(e) => updateField('source_ip', e.target.value)}
                    />
                  </label>

                  <label className="form-field">
                    Destination IP address
                    <input
                      type="text"
                      placeholder="10.0.0.1"
                      value={eventForm.destination_ip}
                      onChange={(e) => updateField('destination_ip', e.target.value)}
                    />
                  </label>

                  <label className="form-field">
                    Destination port
                    <input
                      type="number"
                      min="1"
                      max="65535"
                      placeholder="443"
                      value={eventForm.destination_port}
                      onChange={(e) => updateField('destination_port', e.target.value)}
                    />
                  </label>

                  <label className="form-field">
                    Protocol
                    <input
                      type="text"
                      placeholder="TCP"
                      value={eventForm.protocol}
                      onChange={(e) => updateField('protocol', e.target.value)}
                    />
                  </label>

                  <label className="form-field features-field">
                    Features
                    <small className="features-hint">
                      JSON object of numerical network-flow features. ML inference
                      runs automatically when all 78 trained features are present.
                    </small>
                    <textarea
                      className={featuresParseError ? 'features-textarea features-textarea-error' : 'features-textarea'}
                      rows={6}
                      spellCheck={false}
                      value={eventForm.features_json}
                      onChange={(e) => updateField('features_json', e.target.value)}
                      required
                    />
                    {featuresParseError && (
                      <span className="features-parse-error">{featuresParseError}</span>
                    )}
                  </label>
                </div>

                <div className="form-actions">
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => {
                      setEventForm(EMPTY_FORM)
                      setFormError('')
                      setFeaturesParseError('')
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
                    {submitting ? 'Submitting...' : 'Submit event'}
                  </button>
                </div>

                {formError && (
                  <div className="form-message form-error">
                    <AlertTriangle size={17} />
                    <span>{formError}</span>
                  </div>
                )}

                {result && <EventResult result={result} />}
              </form>
            )}
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
                <small>{API}</small>
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
                    <th>Status</th>
                    <th>Detection Reasons</th>
                    <th>Created At</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((incident) => (
                    <tr
                      key={incident.incident_id}
                      className="incident-row-clickable"
                      onClick={() => openIncidentDetail(incident.incident_id)}
                    >
                      <td className="incident-id">
                        <div className="incident-id-cell">
                          <span>#{incident.incident_id}</span>
                          <span className={`connector-source-badge ${getIncidentSourceBadge(incident).class}`}>
                            {getIncidentSourceBadge(incident).label}
                          </span>
                          {incident.event_count > 1 && (
                            <span className="event-count-pill" title={`${incident.event_count} correlated flows`}>
                              x{incident.event_count}
                            </span>
                          )}
                        </div>
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
                      <td>
                        <span
                          className={`status-tag status-tag-${(incident.status || 'open').toLowerCase()}`}
                        >
                          {incident.status || 'OPEN'}
                        </span>
                      </td>
                      <td className="reason-cell">{incident.reasons}</td>
                      <td className="date-cell">
                        {formatDate(incident.created_at)}
                      </td>
                      <td>
                        <button
                          className="view-details-button"
                          onClick={(e) => {
                            e.stopPropagation()
                            openIncidentDetail(incident.incident_id)
                          }}
                          aria-label={`View details for incident ${incident.incident_id}`}
                        >
                          <Eye size={14} />
                          <span>View</span>
                        </button>
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
          <span>SENTRIX · AI Cyber Threat Intelligence Platform</span>
          <span>ML detection · SQLite</span>
        </footer>
      </main>

      {selectedIncidentId !== null && (
        <IncidentDetailsDrawer
          incidentId={selectedIncidentId}
          detail={incidentDetail}
          loading={detailLoading}
          error={detailError}
          onClose={closeIncidentDetail}
          onStatusUpdated={handleIncidentStatusUpdated}
          csrfToken={csrfToken}
          authUser={authUser}
          onLogout={handleLogout}
        />
      )}
    </div>
  )
}

function IncidentDetailsDrawer({
  incidentId,
  detail,
  loading,
  error,
  onClose,
  onStatusUpdated,
  csrfToken,
  authUser,
  onLogout,
}) {
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [statusError, setStatusError] = useState('')
  const [aiAnalyzing, setAiAnalyzing] = useState(false)
  const [aiError, setAiError] = useState('')

  // Milestone 6: Notes & Assignment state
  const [noteAuthor, setNoteAuthor] = useState(authUser?.username || 'SecOps Analyst')
  const [noteContent, setNoteContent] = useState('')
  const [submittingNote, setSubmittingNote] = useState(false)
  const [noteError, setNoteError] = useState('')

  const [isEditingAssignee, setIsEditingAssignee] = useState(false)
  const [assigneeInput, setAssigneeInput] = useState(detail?.assigned_to || '')
  const [assigning, setAssigning] = useState(false)
  const [assignError, setAssignError] = useState('')

  // Milestone 8: Response Action & Containment state
  const [responseActionLoading, setResponseActionLoading] = useState(false)
  const [responseActionError, setResponseActionError] = useState('')
  const [proposingType, setProposingType] = useState('BLOCK_IP')

  useEffect(() => {
    setStatusError('')
    setStatusUpdating(false)
    setAiError('')
    setAiAnalyzing(false)
    setNoteContent('')
    setNoteError('')
    setIsEditingAssignee(false)
    setAssignError('')
    setAssigneeInput(detail?.assigned_to || '')
    setResponseActionError('')
    setResponseActionLoading(false)
  }, [incidentId, detail?.assigned_to])

  async function handleAssignSubmit() {
    if (!assigneeInput.trim()) return
    setAssigning(true)
    setAssignError('')

    try {
      const response = await fetch(`${API}/incidents/${incidentId}/assign`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
        body: JSON.stringify({ assigned_to: assigneeInput.trim() }),
      })
      const data = await response.json()
      if (!response.ok) {
        if (response.status === 401 && onLogout) {
          await onLogout()
          throw new Error('Session expired. Please sign in.')
        }
        throw new Error(data?.detail || 'Assignment failed.')
      }
      setIsEditingAssignee(false)
      if (onStatusUpdated) {
        onStatusUpdated(data)
      }
    } catch (err) {
      setAssignError(err.message || 'Unable to update assignment.')
    } finally {
      setAssigning(false)
    }
  }

  async function handleApproveResponse(responseId) {
    if (responseActionLoading) return
    setResponseActionLoading(true)
    setResponseActionError('')
    try {
      const res = await fetch(`${API}/responses/${responseId}/approve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
      })
      const data = await res.json()
      if (!res.ok) {
        if (res.status === 401 && onLogout) {
          await onLogout()
          throw new Error('Session expired. Please sign in.')
        }
        throw new Error(data?.detail || 'Approval failed.')
      }
      const updatedIncidentRes = await fetch(`${API}/incidents/${incidentId}`, {
        credentials: 'include',
      })
      if (updatedIncidentRes.ok) {
        const updatedIncident = await updatedIncidentRes.json()
        if (onStatusUpdated) onStatusUpdated(updatedIncident)
      }
    } catch (err) {
      setResponseActionError(err.message || 'Failed to approve containment.')
    } finally {
      setResponseActionLoading(false)
    }
  }

  async function handleRejectResponse(responseId) {
    if (responseActionLoading) return
    setResponseActionLoading(true)
    setResponseActionError('')
    try {
      const res = await fetch(`${API}/responses/${responseId}/reject`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
      })
      const data = await res.json()
      if (!res.ok) {
        if (res.status === 401 && onLogout) {
          await onLogout()
          throw new Error('Session expired. Please sign in.')
        }
        throw new Error(data?.detail || 'Rejection failed.')
      }
      const updatedIncidentRes = await fetch(`${API}/incidents/${incidentId}`, {
        credentials: 'include',
      })
      if (updatedIncidentRes.ok) {
        const updatedIncident = await updatedIncidentRes.json()
        if (onStatusUpdated) onStatusUpdated(updatedIncident)
      }
    } catch (err) {
      setResponseActionError(err.message || 'Failed to reject containment.')
    } finally {
      setResponseActionLoading(false)
    }
  }

  async function handleRollbackResponse(responseId) {
    if (responseActionLoading) return
    setResponseActionLoading(true)
    setResponseActionError('')
    try {
      const res = await fetch(`${API}/responses/${responseId}/rollback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
      })
      const data = await res.json()
      if (!res.ok) {
        if (res.status === 401 && onLogout) {
          await onLogout()
          throw new Error('Session expired. Please sign in.')
        }
        throw new Error(data?.detail || 'Rollback failed.')
      }
      const updatedIncidentRes = await fetch(`${API}/incidents/${incidentId}`, {
        credentials: 'include',
      })
      if (updatedIncidentRes.ok) {
        const updatedIncident = await updatedIncidentRes.json()
        if (onStatusUpdated) onStatusUpdated(updatedIncident)
      }
    } catch (err) {
      setResponseActionError(err.message || 'Failed to rollback containment.')
    } finally {
      setResponseActionLoading(false)
    }
  }

  async function handleManualProposeResponse() {
    if (responseActionLoading) return
    setResponseActionLoading(true)
    setResponseActionError('')
    try {
      const res = await fetch(`${API}/incidents/${incidentId}/responses`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
        body: JSON.stringify({
          action_type: proposingType,
          target: detail.source_ip,
        }),
      })
      const data = await res.json()
      if (!res.ok) {
        if (res.status === 401 && onLogout) {
          await onLogout()
          throw new Error('Session expired. Please sign in.')
        }
        throw new Error(data?.detail || 'Failed to propose action.')
      }
      const updatedIncidentRes = await fetch(`${API}/incidents/${incidentId}`, {
        credentials: 'include',
      })
      if (updatedIncidentRes.ok) {
        const updatedIncident = await updatedIncidentRes.json()
        if (onStatusUpdated) onStatusUpdated(updatedIncident)
      }
    } catch (err) {
      setResponseActionError(err.message || 'Failed to propose containment.')
    } finally {
      setResponseActionLoading(false)
    }
  }

  async function handleAddNote(e) {
    e.preventDefault()
    if (!noteContent.trim() || submittingNote) return
    setSubmittingNote(true)
    setNoteError('')

    try {
      const response = await fetch(`${API}/incidents/${incidentId}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
        body: JSON.stringify({
          author: noteAuthor.trim() || authUser?.username || 'SecOps Analyst',
          content: noteContent.trim(),
        }),
      })
      const data = await response.json()
      if (!response.ok) {
        if (response.status === 401 && onLogout) {
          await onLogout()
          throw new Error('Session expired. Please sign in.')
        }
        throw new Error(data?.detail || 'Failed to add note.')
      }
      setNoteContent('')
      if (onStatusUpdated) {
        onStatusUpdated(data)
      }
    } catch (err) {
      setNoteError(err.message || 'Unable to add note.')
    } finally {
      setSubmittingNote(false)
    }
  }

  async function handleTriggerAiAnalysis() {
    if (aiAnalyzing) return
    setAiAnalyzing(true)
    setAiError('')

    try {
      const response = await fetch(`${API}/incidents/${incidentId}/analyze-ai`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
      })

      const data = await response.json()

      if (!response.ok) {
        if (response.status === 401 && onLogout) {
          await onLogout()
          throw new Error('Session expired. Please sign in.')
        }
        const errorDetail =
          typeof data?.detail === 'string'
            ? data.detail
            : Array.isArray(data?.detail)
            ? data.detail.map((item) => item.msg).join(', ')
            : JSON.stringify(data?.detail)
        throw new Error(errorDetail || `AI analysis failed (HTTP ${response.status}).`)
      }

      if (onStatusUpdated) {
        onStatusUpdated(data)
      }
    } catch (err) {
      setAiError(err.message || 'Unable to generate AI analysis.')
    } finally {
      setAiAnalyzing(false)
    }
  }

  async function handleStatusChange(newStatus) {
    if (!newStatus || newStatus === detail?.status) return

    setStatusUpdating(true)
    setStatusError('')

    try {
      const response = await fetch(`${API}/incidents/${incidentId}/status`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-SENTRIX-CSRF': csrfToken,
        },
        credentials: 'include',
        body: JSON.stringify({ status: newStatus }),
      })

      const data = await response.json()

      if (!response.ok) {
        if (response.status === 401 && onLogout) {
          await onLogout()
          throw new Error('Session expired. Please sign in.')
        }
        const errorDetail =
          typeof data?.detail === 'string'
            ? data.detail
            : Array.isArray(data?.detail)
            ? data.detail.map((item) => item.msg).join(', ')
            : JSON.stringify(data?.detail)
        throw new Error(errorDetail || `Status update failed (HTTP ${response.status}).`)
      }

      if (onStatusUpdated) {
        onStatusUpdated(data)
      }
    } catch (err) {
      setStatusError(err.message || 'Unable to update status.')
    } finally {
      setStatusUpdating(false)
    }
  }

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <div className="drawer-panel">
        <div className="drawer-header">
          <div>
            <div className="drawer-breadcrumb">Incident Details</div>
            <h3 className="drawer-title">Incident #{incidentId}</h3>
          </div>
          <button
            className="drawer-close-button"
            onClick={onClose}
            aria-label="Close drawer"
          >
            <X size={18} />
          </button>
        </div>

        <div className="drawer-body">
          {loading && (
            <div className="drawer-loading">
              <Loader2 size={24} className="spin" />
              <span>Loading incident details...</span>
            </div>
          )}

          {error && (
            <div className="drawer-error">
              <AlertTriangle size={17} />
              <div>
                <strong>Failed to load incident</strong>
                <p>{error}</p>
              </div>
            </div>
          )}

          {!loading && !error && detail && (
            <>
              <div className="drawer-meta-grid">
                <div className="drawer-meta-item">
                  <span className="drawer-meta-label">
                    <ShieldAlert size={13} />
                    Severity
                  </span>
                  <span
                    className={`severity-badge severity-${detail.severity?.toLowerCase()}`}
                  >
                    {detail.severity}
                  </span>
                </div>

                <div className="drawer-meta-item">
                  <span className="drawer-meta-label">
                    <Server size={13} />
                    Telemetry Source
                  </span>
                  <span className={`connector-source-badge ${getIncidentSourceBadge(detail).class}`}>
                    {getIncidentSourceBadge(detail).label}
                  </span>
                </div>

                <div className="drawer-meta-item drawer-status-item">
                  <div className="drawer-status-header">
                    <span className="drawer-meta-label">
                      <Activity size={13} />
                      Status
                    </span>
                    {statusUpdating && (
                      <span className="drawer-status-updating">
                        <Loader2 size={11} className="spin" />
                        <span>Updating...</span>
                      </span>
                    )}
                  </div>
                  <div className="drawer-status-control-wrap">
                    {authUser?.role !== 'admin' ? (
                      <>
                        <select
                          className={`drawer-status-select status-tag-${(detail.status || 'open').toLowerCase()} select-disabled`}
                          value={detail.status || 'OPEN'}
                          disabled={true}
                          title="Admin authorization required to change incident status"
                        >
                          {STATUS_OPTIONS.map((statusOption) => (
                            <option key={statusOption} value={statusOption}>
                              {statusOption}
                            </option>
                          ))}
                        </select>
                        <small className="analyst-role-notice">
                          Role: Analyst (Read-only status; Admin required to change)
                        </small>
                      </>
                    ) : (
                      <select
                        className={`drawer-status-select status-tag-${(detail.status || 'open').toLowerCase()}`}
                        value={detail.status || 'OPEN'}
                        onChange={(e) => handleStatusChange(e.target.value)}
                        disabled={statusUpdating}
                        aria-label="Update incident status"
                      >
                        {STATUS_OPTIONS.map((statusOption) => (
                          <option key={statusOption} value={statusOption}>
                            {statusOption}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                </div>

                <div className="drawer-meta-item">
                  <span className="drawer-meta-label">
                    <Gauge size={13} />
                    Risk Score
                  </span>
                  <div className="drawer-risk-display">
                    <span className="drawer-risk-value">{detail.risk_score}</span>
                    <span className="drawer-risk-unit">/ 100</span>
                    <div className="risk-track drawer-risk-track">
                      <div
                        className={`risk-fill risk-${detail.severity?.toLowerCase()}`}
                        style={{
                          width: `${Math.min(100, Math.max(0, detail.risk_score ?? 0))}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>

                <div className="drawer-meta-item">
                  <span className="drawer-meta-label">
                    <Globe size={13} />
                    Source IP
                  </span>
                  <span className="drawer-mono">{detail.source_ip}</span>
                </div>

                <div className="drawer-meta-item">
                  <span className="drawer-meta-label">
                    <Hash size={13} />
                    Event ID
                  </span>
                  <span className="drawer-mono">{detail.event_id}</span>
                </div>

                <div className="drawer-meta-item">
                  <span className="drawer-meta-label">
                    <Clock3 size={13} />
                    Created At
                  </span>
                  <span className="drawer-date">{formatDate(detail.created_at)}</span>
                </div>

                <div className="drawer-meta-item">
                  <span className="drawer-meta-label">
                    <Activity size={13} />
                    Event Multiplier
                  </span>
                  <div className="drawer-count-display">
                    <span className="event-count-pill-large">x{detail.event_count || 1}</span>
                    <small className="drawer-count-hint">correlated flows</small>
                  </div>
                </div>

                <div className="drawer-meta-item">
                  <span className="drawer-meta-label">
                    <Clock3 size={13} />
                    Last Seen
                  </span>
                  <span className="drawer-date">{formatDate(detail.last_seen_at || detail.created_at)}</span>
                </div>

                <div className="drawer-meta-item drawer-assign-item">
                  <div className="drawer-assign-header">
                    <span className="drawer-meta-label">
                      <UserCheck size={13} />
                      Assignee
                    </span>
                    {!isEditingAssignee && (
                      <button
                        type="button"
                        className="drawer-assign-edit-btn"
                        onClick={() => {
                          setAssigneeInput(detail.assigned_to || '')
                          setIsEditingAssignee(true)
                        }}
                      >
                        {detail.assigned_to ? 'Change' : 'Assign'}
                      </button>
                    )}
                  </div>
                  {isEditingAssignee ? (
                    <div className="drawer-assign-input-wrap">
                      <input
                        type="text"
                        className="drawer-assign-input"
                        placeholder="e.g. Tier 2 SOC, Analyst"
                        value={assigneeInput}
                        onChange={(e) => setAssigneeInput(e.target.value)}
                        disabled={assigning}
                      />
                      <div className="drawer-assign-actions">
                        <button
                          type="button"
                          className="drawer-assign-save-btn"
                          onClick={handleAssignSubmit}
                          disabled={assigning || !assigneeInput.trim()}
                        >
                          {assigning ? <Loader2 size={11} className="spin" /> : 'Save'}
                        </button>
                        <button
                          type="button"
                          className="drawer-assign-cancel-btn"
                          onClick={() => setIsEditingAssignee(false)}
                          disabled={assigning}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <span className={`drawer-assignee-badge ${detail.assigned_to ? 'assigned' : 'unassigned'}`}>
                      {detail.assigned_to || 'Unassigned'}
                    </span>
                  )}
                  {assignError && <small className="drawer-assign-error">{assignError}</small>}
                </div>
              </div>

              {statusError && (
                <div className="drawer-status-error">
                  <AlertTriangle size={15} />
                  <div className="drawer-status-error-text">
                    <strong>Failed to update status</strong>
                    <p>{statusError}</p>
                  </div>
                  <button
                    type="button"
                    className="drawer-status-error-dismiss"
                    onClick={() => setStatusError('')}
                    aria-label="Dismiss error"
                  >
                    <X size={14} />
                  </button>
                </div>
              )}

              {/* AI Threat Analyst Report Section */}
              <div className="drawer-ai-section">
                <div className="drawer-section-heading ai-heading">
                  <div className="ai-heading-left">
                    <Sparkles size={14} className="ai-sparkle-icon" />
                    <span>AI Threat Analyst Report</span>
                    {detail.ai_analysis?.provider && (
                      <span className="ai-provider-badge">
                        {detail.ai_analysis.provider}
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    className="ai-reanalyze-button"
                    onClick={handleTriggerAiAnalysis}
                    disabled={aiAnalyzing}
                    title="Re-run AI Analysis"
                  >
                    <RefreshCw size={12} className={aiAnalyzing ? "spin" : ""} />
                    <span>{aiAnalyzing ? "Analyzing..." : "Re-analyze"}</span>
                  </button>
                </div>

                {aiError && (
                  <div className="ai-error-banner">
                    <AlertTriangle size={13} />
                    <span>{aiError}</span>
                  </div>
                )}

                {detail.ai_analysis ? (
                  <div className="ai-analyst-card">
                    <div className="ai-summary-block">
                      <div className="ai-block-label">Executive Summary</div>
                      <p className="ai-summary-text">{detail.ai_analysis.summary}</p>
                    </div>

                    <div className="ai-reasoning-block">
                      <div className="ai-block-label">Grounded Technical Reasoning</div>
                      <p className="ai-reasoning-text">{detail.ai_analysis.analysis}</p>
                    </div>

                    <div className="ai-recommendation-bar">
                      <div className="ai-rec-left">
                        <span className="ai-rec-label">Recommended Action:</span>
                        <span className={`ai-action-pill action-${(detail.ai_analysis.recommended_action || 'monitor').toLowerCase()}`}>
                          {detail.ai_analysis.recommended_action}
                        </span>
                        {detail.ai_analysis.action_target && (
                          <span className="ai-target-pill">{detail.ai_analysis.action_target}</span>
                        )}
                      </div>
                      <div className="ai-rec-right">
                        <span className="ai-confidence-tag">
                          Confidence: <strong>{detail.ai_analysis.confidence || 'MEDIUM'}</strong>
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="ai-empty-card">
                    <span>No AI investigation report generated yet.</span>
                    <button type="button" className="ai-empty-btn" onClick={handleTriggerAiAnalysis} disabled={aiAnalyzing}>
                      Generate AI Investigation
                    </button>
                  </div>
                )}
              </div>

              {/* Milestone 8: Defensive Response & Containment Center Section */}
              <div className="drawer-response-section">
                <div className="drawer-section-heading response-heading">
                  <div className="response-heading-left">
                    <ShieldCheck size={15} className="response-heading-icon" />
                    <span>Defensive Response & Containment Center</span>
                  </div>
                  <span className="response-count-pill">
                    {detail.responses?.length || 0} Rule{(detail.responses?.length || 0) === 1 ? '' : 's'}
                  </span>
                </div>

                {responseActionError && (
                  <div className="response-error-banner">
                    <AlertTriangle size={13} />
                    <span>{responseActionError}</span>
                  </div>
                )}

                <div className="response-actions-list">
                  {detail.responses && detail.responses.length > 0 ? (
                    detail.responses.map((action) => (
                      <div
                        key={action.id}
                        className={`response-action-card card-${(action.status || 'pending').toLowerCase()}`}
                      >
                        <div className="response-card-top">
                          <div className="response-card-target-wrap">
                            <span className={`response-type-pill response-type-${action.action_type.toLowerCase()}`}>
                              {action.action_type}
                            </span>
                            <span className="response-target-text">{action.target}</span>
                          </div>
                          <span className={`response-status-badge response-status-${(action.status || 'pending').toLowerCase()}`}>
                            {action.status === 'PENDING'
                              ? 'PENDING APPROVAL'
                              : action.status === 'EXECUTED'
                              ? 'ACTIVE / CONTAINED'
                              : action.status}
                          </span>
                        </div>

                        {action.execution_output && (
                          <div className="response-execution-log">
                            {action.execution_output}
                          </div>
                        )}

                        <div className="response-meta-row">
                          <span className="response-meta-item">
                            Requested by: <strong>{action.requested_by || 'AIThreatAnalyst'}</strong>
                          </span>
                          {action.approved_by && (
                            <span className="response-meta-item">
                              Approved by: <strong>{action.approved_by}</strong>
                            </span>
                          )}
                          <span className="response-meta-item">
                            Created: <strong>{formatDate(action.created_at)}</strong>
                          </span>
                          {action.executed_at && (
                            <span className="response-meta-item">
                              Executed: <strong>{formatDate(action.executed_at)}</strong>
                            </span>
                          )}
                        </div>

                        {authUser?.role === 'admin' ? (
                          <div className="response-card-actions">
                            {action.status === 'PENDING' && (
                              <>
                                <button
                                  type="button"
                                  className="btn-approve-action"
                                  onClick={() => handleApproveResponse(action.id)}
                                  disabled={responseActionLoading}
                                >
                                  {responseActionLoading ? (
                                    <Loader2 size={11} className="spin" />
                                  ) : (
                                    <CheckCircle size={11} />
                                  )}
                                  <span>Approve & Execute</span>
                                </button>
                                <button
                                  type="button"
                                  className="btn-reject-action"
                                  onClick={() => handleRejectResponse(action.id)}
                                  disabled={responseActionLoading}
                                >
                                  <X size={11} />
                                  <span>Reject</span>
                                </button>
                              </>
                            )}
                            {action.status === 'EXECUTED' && action.is_active && (
                              <button
                                type="button"
                                className="btn-rollback-action"
                                onClick={() => handleRollbackResponse(action.id)}
                                disabled={responseActionLoading}
                              >
                                {responseActionLoading ? (
                                  <Loader2 size={11} className="spin" />
                                ) : (
                                  <RotateCcw size={11} />
                                )}
                                <span>Rollback / Unblock</span>
                              </button>
                            )}
                          </div>
                        ) : (
                          <div className="analyst-containment-notice">
                            Analyst View: Read-only containment telemetry. Admin authorization required to approve or rollback rules.
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="responses-empty-card">
                      No containment actions active or proposed for this incident yet.
                    </div>
                  )}
                </div>

                {/* Propose Containment Quick Bar */}
                <div className="propose-containment-wrap">
                  <div className="propose-containment-left">
                    <span>Manual Action:</span>
                    <select
                      className="propose-type-select"
                      value={proposingType}
                      onChange={(e) => setProposingType(e.target.value)}
                      disabled={responseActionLoading}
                    >
                      <option value="BLOCK_IP">BLOCK_IP ({detail.source_ip})</option>
                      <option value="RATE_LIMIT">RATE_LIMIT ({detail.source_ip})</option>
                      <option value="ISOLATE_HOST">ISOLATE_HOST ({detail.source_ip})</option>
                    </select>
                  </div>
                  <button
                    type="button"
                    className="btn-propose-action"
                    onClick={handleManualProposeResponse}
                    disabled={responseActionLoading}
                  >
                    {responseActionLoading ? (
                      <Loader2 size={11} className="spin" />
                    ) : (
                      <PlusCircle size={11} />
                    )}
                    <span>Propose Action</span>
                  </button>
                </div>
              </div>

              {/* Threat Intelligence Card Section */}
              <div className="drawer-threat-intel-section">
                <div className="drawer-section-heading intel-heading">
                  <div className="intel-heading-left">
                    <Globe size={14} />
                    <span>Threat Intelligence (AbuseIPDB)</span>
                  </div>
                  {detail.threat_intel && (
                    <span
                      className={`intel-badge intel-badge-${(detail.threat_intel.status || 'unknown').toLowerCase()}`}
                    >
                      {detail.threat_intel.status}
                    </span>
                  )}
                </div>

                {!detail.threat_intel ? (
                  <div className="intel-empty-card">
                    No threat intelligence record attached to this incident.
                  </div>
                ) : (
                  <div className="threat-intel-card">
                    {detail.threat_intel.is_private && (
                      <div className="intel-private-banner">
                        <Info size={14} />
                        <span>Internal / RFC-1918 Private Address (No external reputation query required)</span>
                      </div>
                    )}

                    <div className="intel-score-box">
                      <div className="intel-score-header">
                        <span className="intel-score-title">Abuse Confidence Score</span>
                        <span className="intel-score-number">
                          {detail.threat_intel.abuse_confidence_score ?? 0}
                          <small>/100</small>
                        </span>
                      </div>
                      <div className="intel-score-track">
                        <div
                          className={`intel-score-fill score-${(detail.threat_intel.status || 'unknown').toLowerCase()}`}
                          style={{
                            width: `${Math.min(
                              100,
                              Math.max(0, detail.threat_intel.abuse_confidence_score ?? 0)
                            )}%`,
                          }}
                        />
                      </div>
                    </div>

                    <div className="intel-metrics-grid">
                      <div className="intel-metric-item">
                        <span className="intel-metric-label">Total Reports</span>
                        <span className="intel-metric-val">
                          {detail.threat_intel.total_reports ?? 0}
                        </span>
                      </div>

                      <div className="intel-metric-item">
                        <span className="intel-metric-label">Country Code</span>
                        <span className="intel-metric-val">
                          {detail.threat_intel.country_code ? (
                            <span className="intel-country-tag">
                              {detail.threat_intel.country_code}
                            </span>
                          ) : (
                            'N/A'
                          )}
                        </span>
                      </div>

                      <div className="intel-metric-item intel-span-2">
                        <span className="intel-metric-label">Usage Type / Domain</span>
                        <span className="intel-metric-val">
                          {[detail.threat_intel.usage_type, detail.threat_intel.domain]
                            .filter(Boolean)
                            .join(' · ') || 'N/A'}
                        </span>
                      </div>

                      <div className="intel-metric-item intel-span-2">
                        <span className="intel-metric-label">Data Source</span>
                        <span className="intel-metric-val">
                          {detail.threat_intel.source || 'AbuseIPDB'}
                          {detail.threat_intel.last_reported_at && (
                            <span className="intel-last-reported">
                              {' '}· Last reported: {formatDate(detail.threat_intel.last_reported_at)}
                            </span>
                          )}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Mapping Section */}
              <div className="drawer-mitre-section">
                <div className="drawer-section-heading">
                  <ShieldAlert size={14} />
                  <span>MITRE ATT&CK Mapping</span>
                </div>
                {detail.mitre_attack ? (
                  <div className="mitre-card">
                    <div className="mitre-header">
                      <span className="mitre-badge">{detail.mitre_attack.technique_id}</span>
                      <span className="mitre-name">{detail.mitre_attack.technique_name}</span>
                    </div>
                    <div className="mitre-tactic-row">
                      <span className="mitre-tactic-label">Tactic:</span>
                      <span className="mitre-tactic">{detail.mitre_attack.tactic}</span>
                    </div>
                  </div>
                ) : (
                  <div className="mitre-empty">No MITRE ATT&CK technique mapped.</div>
                )}
              </div>

              {/* Correlated Events Timeline Section */}
              <div className="drawer-timeline-section">
                <div className="drawer-section-heading">
                  <Clock3 size={14} />
                  <span>Correlated Events Timeline ({detail.correlated_events?.length || 1})</span>
                </div>
                <div className="correlated-timeline">
                  {detail.correlated_events && detail.correlated_events.length > 0 ? (
                    detail.correlated_events.map((evt, idx) => (
                      <div key={evt.event_id || idx} className="timeline-item">
                        <div className="timeline-marker" />
                        <div className="timeline-content">
                          <div className="timeline-top">
                            <span className="timeline-id">Flow #{idx + 1}: {evt.event_id ? evt.event_id.slice(0, 8) + '...' : 'Direct Ingest'}</span>
                            {evt.destination_port && (
                              <span className="timeline-port">Port {evt.destination_port}</span>
                            )}
                          </div>
                          <span className="timeline-time">{formatDate(evt.timestamp)}</span>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="timeline-item">
                      <div className="timeline-marker" />
                      <div className="timeline-content">
                        <div className="timeline-top">
                          <span className="timeline-id">Originating Event</span>
                        </div>
                        <span className="timeline-time">{formatDate(detail.created_at)}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="drawer-reasons-section">
                <div className="drawer-section-heading">
                  <FileText size={14} />
                  <span>Detection Reasons</span>
                </div>
                <div className="drawer-reasons-content">
                  {detail.reasons || 'No detection reasons recorded.'}
                </div>
              </div>

              {/* Milestone 6: Analyst Investigation & Notes Section */}
              <div className="drawer-investigation-section">
                <div className="drawer-section-heading">
                  <MessageSquare size={14} />
                  <span>Investigation Notes & Activity Trail ({detail.investigation_notes?.length || 0})</span>
                </div>

                <div className="investigation-notes-list">
                  {detail.investigation_notes && detail.investigation_notes.length > 0 ? (
                    detail.investigation_notes.map((note, idx) => (
                      <div key={note.note_id || idx} className="investigation-note-card">
                        <div className="note-card-header">
                          <span className="note-author-badge">{note.author || 'SecOps Analyst'}</span>
                          <span className="note-date">{formatDate(note.created_at)}</span>
                        </div>
                        <p className="note-content-text">{note.content}</p>
                      </div>
                    ))
                  ) : (
                    <div className="notes-empty-card">
                      No analyst notes recorded yet. Add observations below.
                    </div>
                  )}
                </div>

                <form className="add-note-form" onSubmit={handleAddNote}>
                  <div className="add-note-inputs">
                    <input
                      type="text"
                      className="note-author-input"
                      placeholder="Analyst Name / Team"
                      value={noteAuthor}
                      onChange={(e) => setNoteAuthor(e.target.value)}
                      disabled={submittingNote}
                    />
                    <textarea
                      className="note-content-textarea"
                      placeholder="Enter investigation observations, containment steps, or triage rationale..."
                      rows={2}
                      value={noteContent}
                      onChange={(e) => setNoteContent(e.target.value)}
                      disabled={submittingNote}
                    />
                  </div>
                  {noteError && <div className="note-error-msg">{noteError}</div>}
                  <div className="add-note-actions">
                    <button
                      type="submit"
                      className="add-note-btn"
                      disabled={submittingNote || !noteContent.trim()}
                    >
                      {submittingNote ? (
                        <>
                          <Loader2 size={12} className="spin" />
                          <span>Saving...</span>
                        </>
                      ) : (
                        <>
                          <Send size={12} />
                          <span>Add Note</span>
                        </>
                      )}
                    </button>
                  </div>
                </form>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  )
}

function EventResult({ result }) {
  const status = result.analysis_status

  if (status === 'COMPLETED') {
    const isAttack = result.predicted_label === 'ATTACK'
    return (
      <div className={`form-message ${isAttack ? 'form-error' : 'form-success'}`}>
        {isAttack ? <AlertTriangle size={17} /> : <CircleCheck size={18} />}
        <div>
          <strong>
            ML prediction: {result.predicted_label}
            {' '}· Attack probability: {(result.attack_probability * 100).toFixed(1)}%
          </strong>
          {isAttack && result.incident_created && (
            <p>Incident #{result.incident_id} created · Risk score: {result.risk_score ?? Math.round(result.attack_probability * 100)}/100</p>
          )}
          {isAttack && !result.incident_created && result.incident_id && (
            <p>Existing incident #{result.incident_id} · no duplicate created.</p>
          )}
          {!isAttack && (
            <p>Event stored. No incident created.</p>
          )}
          <p className="result-meta">Event ID: {result.event_id} · Model: {result.model_type}</p>
        </div>
      </div>
    )
  }

  if (status === 'PENDING') {
    return (
      <div className="form-message form-pending">
        <Activity size={17} />
        <div>
          <strong>Event stored — ML inference pending</strong>
          <p>
            The submitted feature set does not match the 78 features required
            by the trained model. The event has been persisted and can be
            re-analyzed once a complete feature set is available.
          </p>
          <p className="result-meta">Event ID: {result.event_id}</p>
        </div>
      </div>
    )
  }

  if (status === 'UNAVAILABLE') {
    return (
      <div className="form-message form-pending">
        <AlertTriangle size={17} />
        <div>
          <strong>Event stored — ML model unavailable</strong>
          <p>The model artifact could not be loaded. The event has been persisted.</p>
          <p className="result-meta">Event ID: {result.event_id}</p>
        </div>
      </div>
    )
  }

  // FAILED or unknown
  return (
    <div className="form-message form-pending">
      <AlertTriangle size={17} />
      <div>
        <strong>Event stored — ML inference failed</strong>
        <p>The event was persisted but inference could not complete.</p>
        <p className="result-meta">Event ID: {result.event_id}</p>
      </div>
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
