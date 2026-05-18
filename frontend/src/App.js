import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Download,
  Loader,
  Activity,
  Lock,
  Mail,
  Globe,
  Wifi,
  ChevronRight,
  Clock,
  FileText,
  Zap,
  BarChart2,
  Trash2,
  RefreshCw,
} from "lucide-react";
import "./App.css";

const API = process.env.REACT_APP_API_URL || "http://localhost:8000";
const API_KEY = process.env.REACT_APP_API_KEY || "";

const apiFetch = (url, opts = {}) => {
  const headers = {
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  return fetch(url, { ...opts, headers });
};

const STEPS = [
  {
    icon: Wifi,
    label: "Network & port scan",
    sub: "Checking RDP, SMB, open databases...",
  },
  {
    icon: Lock,
    label: "SSL/TLS certificate",
    sub: "Validating encryption strength...",
  },
  {
    icon: Mail,
    label: "Email security (SPF/DMARC)",
    sub: "Checking phishing defences...",
  },
  {
    icon: Globe,
    label: "Web application headers",
    sub: "Scanning for misconfigurations...",
  },
];

function riskColor(score) {
  if (score <= 30) return "#10b981";
  if (score <= 60) return "#f59e0b";
  return "#ef4444";
}

function levelColor(level) {
  const m = {
    LOW: "#10b981",
    MEDIUM: "#f59e0b",
    HIGH: "#f97316",
    CRITICAL: "#ef4444",
  };
  return m[level] || "#64748b";
}

/* ── Gauge ── */
function Gauge({ score, level }) {
  const r = 52,
    circ = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score));
  const col = riskColor(pct);
  return (
    <div className="gauge-wrap">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth="10"
        />
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke={col}
          strokeWidth="10"
          strokeDasharray={`${(pct / 100) * circ} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{
            transition: "stroke-dasharray 1.3s cubic-bezier(.4,0,.2,1)",
          }}
        />
        <text
          x="70"
          y="62"
          textAnchor="middle"
          fill={col}
          fontSize="28"
          fontWeight="700"
          fontFamily="'DM Mono',monospace"
        >
          {score}
        </text>
        <text x="70" y="80" textAnchor="middle" fill="#475569" fontSize="11">
          /100
        </text>
      </svg>
      <div className="gauge-level" style={{ color: col }}>
        {level}
      </div>
    </div>
  );
}

function SevBadge({ s }) {
  return <span className={`sev-badge ${s?.toLowerCase()}`}>{s}</span>;
}

function VulnList({ vulns }) {
  if (!vulns?.length)
    return (
      <div className="empty-state">
        <CheckCircle size={16} /> No issues detected
      </div>
    );
  return (
    <div className="vuln-list">
      {vulns.map((v, i) => (
        <div key={i} className={`vuln-item sev-${v.severity?.toLowerCase()}`}>
          <div className="vuln-top">
            <SevBadge s={v.severity} />
            <span className="vuln-desc">{v.description}</span>
          </div>
          {v.mitre_attack && (
            <div className="vuln-mitre">
              <a
                href={v.mitre_url}
                target="_blank"
                rel="noopener noreferrer"
                className="mitre-badge"
              >
                MITRE ATT&CK {v.mitre_attack}
              </a>
              <span className="mitre-tactic">{v.mitre_tactic}</span>
            </div>
          )}
          {v.impact && (
            <p className="vuln-impact">
              <AlertTriangle size={11} /> {v.impact}
            </p>
          )}
          {v.recommendation && (
            <p className="vuln-fix">
              <ChevronRight size={11} />
              <strong>Fix:</strong> {v.recommendation}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

function ScannerCard({ title, icon: Icon, color, data }) {
  const [open, setOpen] = useState(false);
  const vulns = data?.vulnerabilities || [];
  return (
    <div className="scanner-row">
      <button className="scanner-btn" onClick={() => setOpen((o) => !o)}>
        <div className="scanner-left">
          <Icon size={15} color={color} />
          {title}
        </div>
        <div className="scanner-right">
          {vulns.length > 0 ? (
            <span className="scanner-issues" style={{ color }}>
              {vulns.length} issue{vulns.length !== 1 ? "s" : ""}
            </span>
          ) : (
            <span className="scanner-clean">
              <CheckCircle size={13} /> Clean
            </span>
          )}
          <ChevronRight
            size={14}
            className={`chevron-icon ${open ? "open" : ""}`}
          />
        </div>
      </button>
      {open && (
        <div className="scanner-body">
          <VulnList vulns={vulns} />
        </div>
      )}
    </div>
  );
}

/* ── Mini risk bar for history table ── */
function RiskBar({ score, level }) {
  const col = levelColor(level);
  return (
    <div className="risk-bar-wrap">
      <div className="risk-bar-track">
        <div
          className="risk-bar-fill"
          style={{ width: `${Math.min(100, score)}%`, background: col }}
        />
      </div>
      <span className="risk-bar-num" style={{ color: col }}>
        {score}
      </span>
    </div>
  );
}

/* ── History dashboard ── */
function HistoryDashboard({ history, onRescan, onDownload, loading }) {
  if (loading)
    return (
      <div className="hist-loading">
        <Loader size={18} className="spin" /> Loading scan history...
      </div>
    );
  if (!history.length)
    return (
      <div className="hist-empty">
        <BarChart2 size={32} color="#1e3a5f" />
        <p>No scans yet</p>
        <span>Run your first scan to see history here</span>
      </div>
    );

  const avg = Math.round(
    history.reduce((a, h) => a + (h.risk_score || 0), 0) / history.length,
  );
  const critical = history.filter((h) => h.risk_level === "CRITICAL").length;
  const latest = history[0];

  return (
    <div className="hist-wrap">
      {/* Summary stats */}
      <div className="hist-stats">
        <div className="hstat">
          <div className="hstat-val">{history.length}</div>
          <div className="hstat-label">Total scans</div>
        </div>
        <div className="hstat">
          <div className="hstat-val" style={{ color: riskColor(avg) }}>
            {avg}
          </div>
          <div className="hstat-label">Avg risk score</div>
        </div>
        <div className="hstat">
          <div
            className="hstat-val"
            style={{ color: critical > 0 ? "#ef4444" : "#10b981" }}
          >
            {critical}
          </div>
          <div className="hstat-label">Critical targets</div>
        </div>
        <div className="hstat">
          <div
            className="hstat-val"
            style={{ color: levelColor(latest?.risk_level) }}
          >
            {latest?.risk_level || "—"}
          </div>
          <div className="hstat-label">Latest result</div>
        </div>
      </div>

      {/* Table */}
      <div className="hist-table-wrap">
        <table className="hist-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Risk score</th>
              <th>Level</th>
              <th>Scanned</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {history.map((h, i) => (
              <tr key={i} className="hist-row">
                <td className="hist-target">
                  <div className={`hist-dot ${h.risk_level?.toLowerCase()}`} />
                  <span>{h.target}</span>
                </td>
                <td>
                  <RiskBar score={h.risk_score || 0} level={h.risk_level} />
                </td>
                <td>
                  <span
                    className="hist-level"
                    style={{ color: levelColor(h.risk_level) }}
                  >
                    {h.risk_level}
                  </span>
                </td>
                <td className="hist-time">
                  {h.scan_time
                    ? new Date(h.scan_time).toLocaleDateString("en-CA", {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })
                    : "—"}
                </td>
                <td>
                  <div className="hist-actions">
                    <button
                      className="hact-btn"
                      title="Re-scan"
                      onClick={() => onRescan(h.target)}
                    >
                      <RefreshCw size={13} />
                    </button>
                    {h.pdf_filename && (
                      <button
                        className="hact-btn"
                        title="Download PDF"
                        onClick={() => onDownload(h.pdf_filename)}
                      >
                        <Download size={13} />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ── Main App ── */
export default function App() {
  const [tab, setTab] = useState("scan"); // "scan" | "history"
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [step, setStep] = useState(0);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [histLoad, setHistLoad] = useState(false);
  const timer = useRef(null);

  useEffect(() => {
    loadHistory();
  }, []);

  useEffect(() => {
    if (tab === "history") loadHistory();
  }, [tab]);

  const loadHistory = async () => {
    setHistLoad(true);
    try {
      const d = await apiFetch(`${API}/api/reports`).then((r) => r.json());
      const all = Array.isArray(d) ? d : [];
      // Only show scans from last 2 hours for privacy
      const cutoff = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
      setHistory(all.filter((r) => r.scan_time && r.scan_time > cutoff));
    } catch (_) {
      setHistory([]);
    } finally {
      setHistLoad(false);
    }
  };

  const startScan = async (overrideTarget) => {
    const t = (overrideTarget || target).trim();
    if (!t) {
      setError("Please enter a target domain or IP address");
      return;
    }
    setTab("scan");
    setTarget(t);
    setScanning(true);
    setError(null);
    setResults(null);
    setStep(0);
    timer.current = setInterval(
      () => setStep((p) => (p < STEPS.length - 1 ? p + 1 : p)),
      20000,
    );
    try {
      const res = await apiFetch(`${API}/api/scan`, {
        method: "POST",
        body: JSON.stringify({ target: t }),
      });
      clearInterval(timer.current);
      if (!res.ok) throw new Error((await res.json()).detail || "Scan failed");
      setResults(await res.json());
      setStep(STEPS.length);
      loadHistory();
    } catch (e) {
      setError(
        e.message || "Could not connect to scanner. Is the backend running?",
      );
    } finally {
      clearInterval(timer.current);
      setScanning(false);
    }
  };

  const downloadPDF = async (filename) => {
    if (filename) {
      window.open(`${API}/api/download-pdf/${filename}`, "_blank");
      return;
    }
    try {
      const data = await apiFetch(`${API}/api/reports`).then((r) => r.json());
      const reports = Array.isArray(data) ? data : [];
      const clean = (t) =>
        (t || "")
          .replace(/^https?:\/\//, "")
          .replace(/\/$/, "")
          .toLowerCase();
      const cur = clean(results?.target);
      const report =
        reports.find((r) => clean(r.target) === cur) ||
        reports.find(
          (r) => clean(r.target).includes(cur) || cur.includes(clean(r.target)),
        ) ||
        reports[0];
      if (report?.pdf_filename) {
        window.open(`${API}/api/download-pdf/${report.pdf_filename}`, "_blank");
      } else {
        alert(
          "PDF still generating — wait 10 seconds after scan and try again.",
        );
      }
    } catch (e) {
      alert("Failed: " + e.message);
    }
  };

  const risk = results?.overall_risk || {};
  const rr = results?.ransomware_readiness || {};
  const allVulns = risk.vulnerabilities || [];
  const rrScore = rr.readiness_score || 0;
  const rrCol =
    rrScore >= 70 ? "#10b981" : rrScore >= 50 ? "#f59e0b" : "#ef4444";

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-inner">
          <div className="logo">
            <div className="logo-icon">
              <Shield size={20} color="#fff" />
            </div>
            <div>
              <h1>SecureScore</h1>
              <div className="logo-tag">Ransomware readiness</div>
            </div>
          </div>
          <nav className="header-nav">
            <button
              className={`nav-tab ${tab === "scan" ? "active" : ""}`}
              onClick={() => setTab("scan")}
            >
              <Shield size={13} /> Scanner
            </button>
            <button
              className={`nav-tab ${tab === "history" ? "active" : ""}`}
              onClick={() => setTab("history")}
            >
              <BarChart2 size={13} /> History
              {history.length > 0 && (
                <span className="nav-count">{history.length}</span>
              )}
            </button>
            <div className="nav-pill">
              <span className="live-dot" />
              Live
            </div>
          </nav>
        </div>
      </header>

      <main className="main">
        <div className="container">
          {/* ══ SCAN TAB ══ */}
          {tab === "scan" && (
            <>
              {!results && (
                <div className="hero">
                  <div className="hero-eyebrow">
                    <Zap size={11} /> Instant security assessment
                  </div>
                  <h2>
                    Is your business ready for a <span>ransomware attack?</span>
                  </h2>
                  <p>
                    Scan any domain or IP in under 60 seconds. Get a
                    professional security report and know exactly what to fix —
                    no technical knowledge needed.
                  </p>
                </div>
              )}

              <div className="scan-box">
                <div className="input-row">
                  <input
                    className="scan-input"
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="yourdomain.com or 192.168.1.1"
                    disabled={scanning}
                    onKeyDown={(e) => e.key === "Enter" && startScan()}
                  />
                  <button
                    className="scan-btn"
                    onClick={() => startScan()}
                    disabled={scanning}
                  >
                    {scanning ? (
                      <>
                        <Loader size={16} className="spin" /> Scanning...
                      </>
                    ) : (
                      <>
                        <Shield size={16} /> Start Scan
                      </>
                    )}
                  </button>
                </div>

                {error && (
                  <div className="error-bar">
                    <XCircle size={14} />
                    {error}
                  </div>
                )}

                {scanning && (
                  <div className="scan-progress">
                    <div className="progress-header">
                      <Activity size={12} /> Running assessment
                    </div>
                    <div className="progress-steps">
                      {STEPS.map((s, i) => {
                        const Icon = s.icon;
                        const state =
                          i < step ? "done" : i === step ? "active" : "pending";
                        return (
                          <div key={i} className={`progress-step ${state}`}>
                            <div className="step-node">
                              {state === "done" ? (
                                <CheckCircle size={13} />
                              ) : state === "active" ? (
                                <Loader size={13} className="spin" />
                              ) : (
                                <Icon size={13} />
                              )}
                            </div>
                            <div className="step-content">
                              <div className="step-name">{s.label}</div>
                              {state === "active" && (
                                <div className="step-sub">{s.sub}</div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              {/* Recent chips */}
              {history.length > 0 && !results && !scanning && (
                <div className="recent-bar">
                  <div className="recent-label">
                    <Clock size={11} /> Recent
                  </div>
                  <div className="recent-chips">
                    {history.slice(0, 6).map((h, i) => (
                      <button
                        key={i}
                        className="recent-chip"
                        onClick={() => startScan(h.target)}
                      >
                        <span
                          className={`chip-dot ${h.risk_level?.toLowerCase()}`}
                        />
                        {h.target}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Results */}
              {results && (
                <div className="results">
                  <div className="score-grid">
                    <div className="score-card">
                      <div className="sc-label">Overall security risk</div>
                      <Gauge
                        score={risk.total_risk_score || 0}
                        level={`${risk.risk_level || "UNKNOWN"} RISK`}
                      />
                      <div className="vc-row">
                        {risk.critical_count > 0 && (
                          <span className="vc critical">
                            {risk.critical_count} Critical
                          </span>
                        )}
                        {risk.high_count > 0 && (
                          <span className="vc high">
                            {risk.high_count} High
                          </span>
                        )}
                        {risk.medium_count > 0 && (
                          <span className="vc medium">
                            {risk.medium_count} Medium
                          </span>
                        )}
                        {risk.low_count > 0 && (
                          <span className="vc low">{risk.low_count} Low</span>
                        )}
                        {!risk.total_vulnerabilities && (
                          <span className="vc low">0 issues found</span>
                        )}
                      </div>
                    </div>

                    <div className="score-card">
                      <div className="sc-label">Ransomware readiness</div>
                      <div
                        className="readiness-level"
                        data-l={rr.readiness_level}
                      >
                        {rr.readiness_level || "—"}
                      </div>
                      <div className="rb-wrap">
                        <div className="rb-track">
                          <div
                            className="rb-fill"
                            style={{ width: `${rrScore}%`, background: rrCol }}
                          />
                        </div>
                        <span className="rb-num" style={{ color: rrCol }}>
                          {rrScore}/100
                        </span>
                      </div>
                      <div className="rm-list">
                        <div className="rm-row">
                          <span className="rm-key">Survive attack</span>
                          {rr.can_survive_attack ? (
                            <span className="rm-yes">
                              <CheckCircle size={13} /> Yes
                            </span>
                          ) : (
                            <span className="rm-no">
                              <XCircle size={13} /> No
                            </span>
                          )}
                        </div>
                        <div className="rm-row">
                          <span className="rm-key">Insurance ready</span>
                          {rr.insurance_ready ? (
                            <span className="rm-yes">
                              <CheckCircle size={13} /> Yes
                            </span>
                          ) : (
                            <span className="rm-no">
                              <XCircle size={13} /> No
                            </span>
                          )}
                        </div>
                        <div className="rm-row">
                          <span className="rm-key">Recovery time</span>
                          <span className="rm-val">
                            <Clock size={12} />
                            {rr.estimated_recovery_time || "—"}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {allVulns.length > 0 && (
                    <div className="panel">
                      <div className="panel-header">
                        <AlertTriangle size={15} color="#f59e0b" />
                        <div className="panel-title">
                          All vulnerabilities{" "}
                          <span className="badge-count warn">
                            {allVulns.length}
                          </span>
                        </div>
                      </div>
                      <VulnList vulns={allVulns} />
                    </div>
                  )}

                  <div className="panel">
                    <div className="panel-header">
                      <Activity size={15} color="#3b82f6" />
                      <div className="panel-title">
                        Scanner breakdown{" "}
                        <span className="badge-count info">4 modules</span>
                      </div>
                    </div>
                    <div className="scanner-list">
                      <ScannerCard
                        title="Network & ports"
                        icon={Wifi}
                        color="#ef4444"
                        data={results.network_scan}
                      />
                      <ScannerCard
                        title="SSL / TLS"
                        icon={Lock}
                        color="#3b82f6"
                        data={results.ssl_scan}
                      />
                      <ScannerCard
                        title="Email security"
                        icon={Mail}
                        color="#f59e0b"
                        data={results.email_scan}
                      />
                      <ScannerCard
                        title="Web application"
                        icon={Globe}
                        color="#8b5cf6"
                        data={results.webapp_scan}
                      />
                    </div>
                  </div>

                  {rr.attack_vectors?.length > 0 && (
                    <div className="panel">
                      <div className="panel-header">
                        <Shield size={15} color="#ef4444" />
                        <div className="panel-title">
                          Ransomware attack vectors{" "}
                          <span className="badge-count danger">
                            {rr.attack_vectors.length}
                          </span>
                        </div>
                      </div>
                      <div className="vector-list">
                        {rr.attack_vectors.map((v, i) => (
                          <div
                            key={i}
                            className={`vector-item sev-${v.severity?.toLowerCase()}`}
                          >
                            <div className="vector-top">
                              <SevBadge s={v.severity} />
                              {v.vector}
                            </div>
                            <p className="vector-like">{v.likelihood}</p>
                            <p className="vector-fix">
                              <ChevronRight size={11} />
                              <strong>Fix:</strong> {v.fix}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {risk.recommendations?.length > 0 && (
                    <div className="panel">
                      <div className="panel-header">
                        <CheckCircle size={15} color="#10b981" />
                        <div className="panel-title">
                          Priority recommendations
                        </div>
                      </div>
                      <div className="rec-list">
                        {risk.recommendations.map((r, i) => (
                          <div key={i} className="rec-item">
                            <span className="rec-num">
                              {String(i + 1).padStart(2, "0")}
                            </span>
                            <span className="rec-text">{r}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="action-row">
                    <button
                      className="reset-btn"
                      onClick={() => {
                        setResults(null);
                        setTarget("");
                      }}
                    >
                      Scan another target
                    </button>
                    <button className="dl-btn" onClick={() => downloadPDF()}>
                      <FileText size={15} /> Download PDF report
                    </button>
                  </div>
                </div>
              )}
            </>
          )}

          {/* ══ HISTORY TAB ══ */}
          {tab === "history" && (
            <div className="hist-page">
              <div className="hist-page-header">
                <div>
                  <h2 className="hist-title">Scan history</h2>
                  <p className="hist-sub">
                    All past assessments — click to re-scan or download the PDF
                    report
                  </p>
                </div>
                <button
                  className="hist-refresh"
                  onClick={loadHistory}
                  disabled={histLoad}
                >
                  <RefreshCw size={14} className={histLoad ? "spin" : ""} />
                  Refresh
                </button>
              </div>
              <HistoryDashboard
                history={history}
                loading={histLoad}
                onRescan={(t) => startScan(t)}
                onDownload={(f) => downloadPDF(f)}
              />
            </div>
          )}
        </div>
      </main>

      <footer className="footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <Shield size={16} color="#3b82f6" /> SecureScore
          </div>
          <div className="footer-copy">
            Built by Frederick Ighile · Ransomware Prevention for Canadian SMBs
            · {new Date().getFullYear()}
          </div>
        </div>
      </footer>
    </div>
  );
}
