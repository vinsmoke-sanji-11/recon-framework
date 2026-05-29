import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

type Finding = {
  host:          string;
  exposure_type: string;
  file_path:     string;
  status_code:   number;
  source:        "passive" | "active" | "git";
  extension?:    string;
  critical?:     boolean;
};

type BypassFinding = {
  original_url:   string;
  host:           string;
  origin_ip:      string | null;
  bypass_type:    "header" | "path" | "method";
  bypass_headers: Record<string, string>;
  bypass_path:    string;
  bypass_method?: string;
  status_code:    number;
  via_origin:     boolean;
  source:         string;
  critical:       boolean;
};

type BypassStatus = {
  status:     "not_started" | "running" | "done" | "error";
  total:      number;
  done:       number;
  found:      number;
  viaOrigin?: number;
  viaCDN?:    number;
  error?:     string;
  findings:   BypassFinding[];
};

type Dork = {
  domain:         string;
  dork:           string;
  discovered_url: string;
  title:          string;
  source_engine:  "google" | "bing" | "shodan";
};

type ConfidentialStatus = {
  status:   "not_started" | "running" | "done" | "error";
  findings: number;
  dorks:    number;
  critical?: number;
  bySource?: { passive: number; active: number; git: number };
  error?: string;
};

type FullData = ConfidentialStatus & {
  findings: Finding[] | number;
  dorks:    Dork[]    | number;
};

type APIOptions = {
  googleKey: string;
  googleCX:  string;
  bingKey:   string;
  shodanKey: string;
};

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  error:       "var(--red)",
  not_started: "var(--text-muted)",
};

const SOURCE_COLOR: Record<string, string> = {
  passive: "var(--cyan)",
  active:  "var(--amber)",
  git:     "var(--red)",
};

const ENGINE_COLOR: Record<string, string> = {
  google: "#4285f4",
  bing:   "#00a4ef",
  shodan: "var(--orange)",
};

const BYPASS_TYPE_COLOR: Record<string, string> = {
  header: "var(--green)",
  path:   "var(--cyan)",
  method: "var(--amber)",
};

const STATUS_CODE_COLOR = (code: number) => {
  if (code === 200) return "var(--green)";
  if (code === 403) return "var(--amber)";
  if (code === 401) return "var(--orange)";
  return "var(--text-muted)";
};

type Tab = "findings" | "bypass" | "dorks";
type SourceFilter = "all" | "passive" | "active" | "git";

export default function ConfidentialPage() {
  const [targets, setTargets]     = useState<string[]>([]);
  const [selected, setSelected]   = useState("");
  const [data, setData]           = useState<FullData | null>(null);
  const [loading, setLoading]     = useState(false);
  const [tab, setTab]             = useState<Tab>("findings");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [search, setSearch]       = useState("");
  const [showAPIConfig, setShowAPIConfig] = useState(false);

  // Bypass state
  const [bypassData, setBypassData]     = useState<BypassStatus | null>(null);
  const [bypassLoading, setBypassLoading] = useState(false);
  const bypassPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Module toggles
  const [passive,  setPassive]  = useState(true);
  const [active,   setActive]   = useState(true);
  const [gitCheck, setGitCheck] = useState(true);

  const [apiOpts, setApiOpts] = useState<APIOptions>({
    googleKey: "", googleCX: "", bingKey: "", shodanKey: "",
  });

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadTargets();
    return () => { stopPolling(); stopBypassPolling(); };
  }, []);

  const loadTargets = async () => {
    const res = await axios.get(`${API}/targets`);
    setTargets(res.data || []);
  };

  const selectTarget = async (target: string) => {
    stopPolling();
    stopBypassPolling();
    setSelected(target);
    setData(null);
    setBypassData(null);
    setSearch("");
    setSourceFilter("all");
    setTab("findings");

    const [confRes, bypassRes] = await Promise.all([
      axios.get(`${API}/confidential/${target}`),
      axios.get(`${API}/bypass403/${target}`),
    ]);
    setData(confRes.data);
    setBypassData(bypassRes.data);
    if (confRes.data.status === "running") startPolling(target);
    if (bypassRes.data.status === "running") startBypassPolling(target);
  };

  const runScan = async () => {
    if (!selected) return;
    setLoading(true);
    setData(prev => ({
      ...(prev || {}),
      status: "running" as const,
      findings: [] as any,
      dorks: [] as any,
    } as FullData));
    await axios.post(`${API}/confidential/${selected}`, {
      passive, active, gitCheck,
      googleKey: apiOpts.googleKey || null,
      googleCX:  apiOpts.googleCX  || null,
      bingKey:   apiOpts.bingKey   || null,
      shodanKey: apiOpts.shodanKey || null,
    });
    startPolling(selected);
  };

  const runBypass = async () => {
    if (!selected) return;
    setBypassLoading(true);
    setBypassData({ status: "running", total: 0, done: 0, found: 0, findings: [] });
    setTab("bypass");
    await axios.post(`${API}/bypass403/${selected}`);
    startBypassPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const res = await axios.get(`${API}/confidential/${target}`);
      setData(res.data);
      if (res.data.status !== "running") { stopPolling(); setLoading(false); }
    }, 3000);
  };

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const startBypassPolling = (target: string) => {
    stopBypassPolling();
    bypassPollRef.current = setInterval(async () => {
      const res = await axios.get(`${API}/bypass403/${target}`);
      setBypassData(res.data);
      if (res.data.status !== "running") { stopBypassPolling(); setBypassLoading(false); }
    }, 2000);
  };

  const stopBypassPolling = () => {
    if (bypassPollRef.current) { clearInterval(bypassPollRef.current); bypassPollRef.current = null; }
  };

  const isRunning        = loading        || data?.status        === "running";
  const isBypassRunning  = bypassLoading  || bypassData?.status  === "running";

  const findings: Finding[] = Array.isArray(data?.findings) ? data!.findings as Finding[] : [];
  const dorks:    Dork[]    = Array.isArray(data?.dorks)    ? data!.dorks    as Dork[]    : [];
  const findings403         = findings.filter(f => f.status_code === 403);

  const filteredFindings = findings.filter(f => {
    if (sourceFilter !== "all" && f.source !== sourceFilter) return false;
    if (search && !f.file_path.toLowerCase().includes(search.toLowerCase()) &&
        !f.host.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const filteredDorks = dorks.filter(d => {
    if (search && !d.discovered_url.toLowerCase().includes(search.toLowerCase()) &&
        !d.dork.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const filteredBypass = (bypassData?.findings || []).filter(b => {
    if (search && !b.original_url.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const anyAPIEnabled = !!(apiOpts.googleKey || apiOpts.bingKey || apiOpts.shodanKey);

  // Bypass progress
  const bypassProgress = bypassData?.total
    ? Math.round((bypassData.done / bypassData.total) * 100)
    : 0;

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 07</div>
          <h1 style={s.title}>Confidential Surface Discovery</h1>
        </div>
        <div style={{ display: "flex", gap: 24 }}>
          {findings.length > 0 && (
            <div style={s.countBox}>
              <span style={{ ...s.countNum, color: findings403.length > 0 ? "var(--amber)" : "var(--cyan)" }}>
                {findings.length}
              </span>
              <span style={s.countLabel}>findings</span>
            </div>
          )}
          {(bypassData?.found || 0) > 0 && (
            <div style={s.countBox}>
              <span style={{ ...s.countNum, color: "var(--red)" }}>{bypassData!.found}</span>
              <span style={s.countLabel}>bypassed</span>
            </div>
          )}
        </div>
      </div>

      <div style={s.layout}>
        {/* Sidebar */}
        <div style={s.sidebar}>
          <div style={s.listLabel}>TARGETS</div>
          {targets.map(t => (
            <button
              key={t}
              onClick={() => selectTarget(t)}
              style={{ ...s.targetBtn, ...(selected === t ? s.targetBtnActive : {}) }}
            >
              <span style={s.targetDot} />{t}
            </button>
          ))}

          {selected && (
            <>
              <div style={{ ...s.listLabel, marginTop: 24 }}>MODULES</div>
              {[
                { label: "Passive scan",  val: passive,  set: setPassive },
                { label: "Active (ffuf)", val: active,   set: setActive },
                { label: "Git exposure",  val: gitCheck, set: setGitCheck },
              ].map(({ label, val, set }) => (
                <label key={label} style={s.toggle}>
                  <div
                    style={{ ...s.toggleSwitch, background: val ? "var(--cyan)" : "var(--border)" }}
                    onClick={() => set(!val)}
                  >
                    <div style={{ ...s.toggleKnob, left: val ? 14 : 2 }} />
                  </div>
                  <span style={s.toggleLabel}>{label}</span>
                </label>
              ))}

              <div style={{ ...s.listLabel, marginTop: 20 }}>DORK APIs</div>
              <button
                onClick={() => setShowAPIConfig(!showAPIConfig)}
                style={s.apiToggleBtn}
              >
                <span style={{
                  width: 6, height: 6, borderRadius: "50%", display: "inline-block",
                  background: anyAPIEnabled ? "var(--green)" : "var(--border-bright)",
                  marginRight: 8, flexShrink: 0,
                }} />
                {anyAPIEnabled ? "APIs configured" : "Configure APIs"}
                <span style={{ marginLeft: "auto" }}>{showAPIConfig ? "▴" : "▾"}</span>
              </button>

              {showAPIConfig && (
                <div style={s.apiPanel}>
                  {[
                    { label: "Google API Key", key: "googleKey",  placeholder: "AIza..." },
                    { label: "Google CX",      key: "googleCX",   placeholder: "cx:..." },
                    { label: "Bing API Key",   key: "bingKey",    placeholder: "abc123..." },
                    { label: "Shodan Key",     key: "shodanKey",  placeholder: "abc123..." },
                  ].map(({ label, key, placeholder }) => (
                    <div key={key} style={{ marginBottom: 8 }}>
                      <div style={s.apiLabel}>{label}</div>
                      <input
                        type="password"
                        value={(apiOpts as Record<string, string>)[key]}
                        onChange={e => setApiOpts(prev => ({ ...prev, [key]: e.target.value }))}
                        placeholder={placeholder}
                        style={s.apiInput}
                        spellCheck={false}
                      />
                    </div>
                  ))}
                  <div style={s.apiHint}>All API keys optional.</div>
                </div>
              )}

              {/* 403 Bypass button */}
              {findings403.length > 0 && (
                <div style={{ marginTop: 20 }}>
                  <div style={s.listLabel}>403 BYPASS</div>
                  <div style={s.bypassInfo}>
                    <span style={{ color: "var(--amber)", fontWeight: 700 }}>{findings403.length}</span>
                    <span style={{ color: "var(--text-muted)" }}> × 403 findings</span>
                  </div>
                  <div style={{ ...s.bypassInfo, marginBottom: 8 }}>
                    <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
                      Uses origin IPs to bypass Cloudflare
                    </span>
                  </div>
                  <button
                    onClick={runBypass}
                    disabled={isBypassRunning}
                    style={{
                      ...s.bypassBtn,
                      opacity: isBypassRunning ? 0.45 : 1,
                      cursor: isBypassRunning ? "not-allowed" : "pointer",
                    }}
                  >
                    {isBypassRunning
                      ? `BYPASSING... ${bypassProgress}%`
                      : bypassData?.found
                      ? `RERUN BYPASS (${bypassData.found} found)`
                      : "RUN 403 BYPASS"}
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Results */}
        <div style={s.results}>
          {!selected ? (
            <div style={s.empty}>
              <div style={s.emptyIcon}>⚿</div>
              <div style={s.emptyText}>Select a target to discover exposed files</div>
              <div style={s.emptyHint}>Passive · Active (ffuf) · Git exposure · 403 bypass</div>
            </div>
          ) : (
            <>
              {/* Toolbar */}
              <div style={s.toolbar}>
                <div style={s.searchBox}>
                  <span style={s.searchIcon}>⌕</span>
                  <input
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    placeholder="Filter findings..."
                    style={s.searchInput}
                    spellCheck={false}
                  />
                  {search && <button onClick={() => setSearch("")} style={s.clearBtn}>✕</button>}
                </div>
                {data && (
                  <div style={{
                    ...s.badge,
                    background: `${STATUS_COLOR[data.status]}22`,
                    border: `1px solid ${STATUS_COLOR[data.status]}`,
                    color: STATUS_COLOR[data.status],
                  }}>
                    <span style={{ ...s.badgeDot, background: STATUS_COLOR[data.status] }}
                      className={isRunning ? "pulse" : ""} />
                    {data.status}
                  </div>
                )}
                <button
                  onClick={runScan}
                  disabled={isRunning}
                  style={{ ...s.runBtn, opacity: isRunning ? 0.45 : 1, cursor: isRunning ? "not-allowed" : "pointer" }}
                >
                  {isRunning ? "SCANNING..." : "RUN SCAN"}
                </button>
              </div>

              {/* Stats */}
              {data?.bySource && (
                <div style={s.statsRow}>
                  {[
                    { label: "passive", val: data.bySource.passive, color: "var(--cyan)" },
                    { label: "active",  val: data.bySource.active,  color: "var(--amber)" },
                    { label: "git",     val: data.bySource.git,     color: "var(--red)" },
                  ].map(({ label, val, color }) => (
                    <div key={label} style={s.stat}>
                      <span style={{ ...s.statNum, color }}>{val}</span>
                      <span style={s.statLabel}>{label}</span>
                    </div>
                  ))}
                  {data.critical !== undefined && data.critical > 0 && (
                    <>
                      <div style={s.statDivider} />
                      <div style={s.stat}>
                        <span style={{ ...s.statNum, color: "var(--red)" }}>⚠ {data.critical}</span>
                        <span style={s.statLabel}>critical</span>
                      </div>
                    </>
                  )}
                  {findings403.length > 0 && (
                    <>
                      <div style={s.statDivider} />
                      <div style={s.stat}>
                        <span style={{ ...s.statNum, color: "var(--amber)", fontSize: 16 }}>{findings403.length}</span>
                        <span style={s.statLabel}>403s</span>
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* Bypass progress bar */}
              {isBypassRunning && bypassData && (
                <div style={s.bypassProgress}>
                  <div style={s.bypassProgressHeader}>
                    <span style={{ color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 11 }}>
                      ⚡ BYPASS RUNNING
                    </span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                      {bypassData.done}/{bypassData.total} · {bypassData.found} bypassed
                    </span>
                  </div>
                  <div style={s.progressBar}>
                    <div style={{ ...s.progressFill, width: `${bypassProgress}%`, background: "var(--red)" }} />
                  </div>
                </div>
              )}

              {/* Tabs */}
              {(findings.length > 0 || (bypassData?.findings || []).length > 0 || dorks.length > 0) && (
                <div style={s.tabRow}>
                  <button
                    onClick={() => setTab("findings")}
                    style={{ ...s.tabBtn, ...(tab === "findings" ? s.tabBtnActive : {}) }}
                  >
                    FINDINGS <span style={s.tabCount}>{findings.length}</span>
                  </button>
                  {(bypassData?.findings || []).length > 0 && (
                    <button
                      onClick={() => setTab("bypass")}
                      style={{
                        ...s.tabBtn,
                        ...(tab === "bypass" ? s.tabBtnActive : {}),
                        color: tab === "bypass" ? "var(--red)" : "var(--text-muted)",
                        borderBottomColor: tab === "bypass" ? "var(--red)" : "transparent",
                      }}
                    >
                      BYPASSED <span style={{ ...s.tabCount, background: "rgba(239,68,68,0.15)", color: "var(--red)" }}>
                        {bypassData!.findings.length}
                      </span>
                    </button>
                  )}
                  {dorks.length > 0 && (
                    <button
                      onClick={() => setTab("dorks")}
                      style={{ ...s.tabBtn, ...(tab === "dorks" ? s.tabBtnActive : {}) }}
                    >
                      DORKS <span style={s.tabCount}>{dorks.length}</span>
                    </button>
                  )}
                </div>
              )}

              {/* Source filter (findings tab) */}
              {tab === "findings" && findings.length > 0 && (
                <div style={s.sourceRow}>
                  {(["all", "passive", "active", "git"] as SourceFilter[]).map(src => (
                    <button
                      key={src}
                      onClick={() => setSourceFilter(src)}
                      style={{
                        ...s.srcBtn,
                        color: sourceFilter === src
                          ? src === "all" ? "var(--text-primary)" : SOURCE_COLOR[src]
                          : "var(--text-muted)",
                        borderBottom: sourceFilter === src
                          ? `2px solid ${src === "all" ? "var(--cyan)" : SOURCE_COLOR[src]}`
                          : "2px solid transparent",
                      }}
                    >
                      {src.toUpperCase()}
                      <span style={s.srcCount}>
                        {src === "all" ? findings.length : findings.filter(f => f.source === src).length}
                      </span>
                    </button>
                  ))}
                </div>
              )}

              {/* Error */}
              {data?.status === "error" && data.error && (
                <div style={s.errorBox}><span>✕</span> {data.error}</div>
              )}

              {/* Not started */}
              {(!data || data.status === "not_started") && !loading && (
                <div style={s.empty}>
                  <div style={s.emptyText}>Click "Run Scan" to start discovery</div>
                  <div style={s.emptyHint}>Toggle modules · Configure API keys for dork discovery</div>
                </div>
              )}

              {/* ── Findings table ──────────────────────────────────────────── */}
              {tab === "findings" && filteredFindings.length > 0 && (
                <div style={s.tableWrap}>
                  <table style={s.table}>
                    <thead>
                      <tr>
                        <th style={s.th}>SOURCE</th>
                        <th style={s.th}>STATUS</th>
                        <th style={s.th}>HOST</th>
                        <th style={s.th}>PATH</th>
                        <th style={s.th}>TYPE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFindings.map((f, i) => (
                        <tr key={i} className="animate-in" style={f.critical ? { background: "rgba(239,68,68,0.04)" } : {}}>
                          <td style={s.td}>
                            <span style={{
                              padding: "2px 7px", borderRadius: 3, fontSize: 9, fontWeight: 700,
                              fontFamily: "var(--font-mono)", letterSpacing: "0.1em",
                              background: `${SOURCE_COLOR[f.source]}22`,
                              border: `1px solid ${SOURCE_COLOR[f.source]}`,
                              color: SOURCE_COLOR[f.source],
                            }}>{f.source}</span>
                          </td>
                          <td style={s.td}>
                            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: STATUS_CODE_COLOR(f.status_code), fontWeight: 700 }}>
                              {f.status_code}
                            </span>
                          </td>
                          <td style={{ ...s.td, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
                            {f.critical && <span style={{ color: "var(--red)", marginRight: 6 }}>⚠</span>}
                            {f.host}
                          </td>
                          <td style={{ ...s.td, maxWidth: 400, wordBreak: "break-all" as const }}>
                            <a href={f.file_path} target="_blank" rel="noopener noreferrer"
                              style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--cyan)", textDecoration: "none" }}>
                              {f.file_path}
                            </a>
                          </td>
                          <td style={{ ...s.td, fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
                            {f.exposure_type}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* ── Bypass results table ────────────────────────────────────── */}
              {tab === "bypass" && (
                <>
                  {filteredBypass.length > 0 ? (
                    <div style={s.tableWrap}>
                      <table style={s.table}>
                        <thead>
                          <tr>
                            <th style={s.th}>TYPE</th>
                            <th style={s.th}>ORIGIN IP</th>
                            <th style={s.th}>ORIGINAL URL</th>
                            <th style={s.th}>BYPASS DETAIL</th>
                            <th style={s.th}>VIA</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredBypass.map((b, i) => (
                            <tr key={i} className="animate-in" style={{ background: "rgba(239,68,68,0.04)" }}>
                              <td style={s.td}>
                                <span style={{
                                  padding: "2px 7px", borderRadius: 3, fontSize: 9, fontWeight: 700,
                                  fontFamily: "var(--font-mono)", letterSpacing: "0.1em",
                                  background: `${BYPASS_TYPE_COLOR[b.bypass_type]}22`,
                                  border: `1px solid ${BYPASS_TYPE_COLOR[b.bypass_type]}`,
                                  color: BYPASS_TYPE_COLOR[b.bypass_type],
                                }}>{b.bypass_type}</span>
                              </td>
                              <td style={{ ...s.td, fontFamily: "var(--font-mono)", fontSize: 11 }}>
                                {b.origin_ip
                                  ? <span style={{ color: "var(--green)" }}>{b.origin_ip}</span>
                                  : <span style={{ color: "var(--text-muted)" }}>CDN</span>
                                }
                              </td>
                              <td style={{ ...s.td, maxWidth: 300, wordBreak: "break-all" as const }}>
                                <a href={b.original_url} target="_blank" rel="noopener noreferrer"
                                  style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--cyan)", textDecoration: "none" }}>
                                  {b.original_url}
                                </a>
                              </td>
                              <td style={{ ...s.td, fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-secondary)", maxWidth: 220 }}>
                                {b.bypass_type === "header" && Object.entries(b.bypass_headers).map(([k, v]) => `${k}: ${v}`).join(", ")}
                                {b.bypass_type === "path"   && b.bypass_path}
                                {b.bypass_type === "method" && b.bypass_method}
                              </td>
                              <td style={s.td}>
                                <span style={{
                                  fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700,
                                  color: b.via_origin ? "var(--green)" : "var(--amber)",
                                }}>
                                  {b.via_origin ? "ORIGIN" : "CDN"}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={s.empty}>
                      <div style={s.emptyText}>
                        {isBypassRunning ? "Bypass running..." : "No 403s bypassed yet"}
                      </div>
                      <div style={s.emptyHint}>
                        {!isBypassRunning && "Run bypass from the left panel"}
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* ── Dorks table ─────────────────────────────────────────────── */}
              {tab === "dorks" && filteredDorks.length > 0 && (
                <div style={s.tableWrap}>
                  <table style={s.table}>
                    <thead>
                      <tr>
                        <th style={s.th}>ENGINE</th>
                        <th style={s.th}>DORK</th>
                        <th style={s.th}>URL</th>
                        <th style={s.th}>TITLE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredDorks.map((d, i) => (
                        <tr key={i} className="animate-in">
                          <td style={s.td}>
                            <span style={{
                              padding: "2px 7px", borderRadius: 3, fontSize: 9, fontWeight: 700,
                              fontFamily: "var(--font-mono)", letterSpacing: "0.1em",
                              background: `${ENGINE_COLOR[d.source_engine]}22`,
                              border: `1px solid ${ENGINE_COLOR[d.source_engine]}`,
                              color: ENGINE_COLOR[d.source_engine],
                            }}>{d.source_engine}</span>
                          </td>
                          <td style={{ ...s.td, fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", maxWidth: 200 }}>
                            {d.dork}
                          </td>
                          <td style={{ ...s.td, maxWidth: 360, wordBreak: "break-all" as const }}>
                            <a href={d.discovered_url} target="_blank" rel="noopener noreferrer"
                              style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--cyan)", textDecoration: "none" }}>
                              {d.discovered_url}
                            </a>
                          </td>
                          <td style={{ ...s.td, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
                            {d.title}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {data?.status === "done" && filteredFindings.length === 0 && tab === "findings" && (
                <div style={s.empty}>
                  <div style={s.emptyText}>
                    {search || sourceFilter !== "all" ? "No findings match filter" : "No exposed files found"}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  header: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 28 },
  phase: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--cyan)", letterSpacing: "0.2em", marginBottom: 6 },
  title: { fontSize: 26, fontWeight: 600, letterSpacing: "-0.02em" },
  countBox: { display: "flex", flexDirection: "column", alignItems: "flex-end" },
  countNum: { fontFamily: "var(--font-mono)", fontSize: 34, fontWeight: 700, color: "var(--cyan)", lineHeight: 1 },
  countLabel: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  layout: { display: "flex", gap: 20, alignItems: "flex-start" },
  sidebar: { width: 200, flexShrink: 0, display: "flex", flexDirection: "column", gap: 4 },
  listLabel: { fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.2em", marginBottom: 6, paddingLeft: 4 },
  targetBtn: {
    display: "flex", alignItems: "center", gap: 8, padding: "9px 11px",
    background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 5,
    color: "var(--text-secondary)", fontFamily: "var(--font-mono)", fontSize: 11,
    cursor: "pointer", textAlign: "left" as const, width: "100%",
    wordBreak: "break-all" as const, transition: "all 0.15s",
  },
  targetBtnActive: { border: "1px solid var(--cyan)", color: "var(--cyan)", background: "var(--cyan-glow)" },
  targetDot: { display: "inline-block", width: 5, height: 5, borderRadius: "50%", background: "currentColor", flexShrink: 0 },
  toggle: { display: "flex", alignItems: "center", gap: 8, padding: "6px 4px", cursor: "pointer" },
  toggleSwitch: { position: "relative" as const, width: 28, height: 16, borderRadius: 8, cursor: "pointer", flexShrink: 0, transition: "background 0.2s" },
  toggleKnob: { position: "absolute" as const, top: 2, width: 12, height: 12, borderRadius: "50%", background: "white", transition: "left 0.2s" },
  toggleLabel: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" },
  apiToggleBtn: {
    display: "flex", alignItems: "center", gap: 0, padding: "7px 10px",
    background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 5,
    fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)",
    cursor: "pointer", width: "100%", marginTop: 2,
  },
  apiPanel: { padding: "10px", background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 5, marginTop: 4 },
  apiLabel: { fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em", marginBottom: 4 },
  apiInput: {
    width: "100%", background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 4, padding: "5px 8px", fontFamily: "var(--font-mono)", fontSize: 11,
    color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const,
  },
  apiHint: { fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", marginTop: 8, lineHeight: 1.5 },
  bypassInfo: { fontFamily: "var(--font-mono)", fontSize: 11, padding: "2px 4px" },
  bypassBtn: {
    width: "100%", padding: "9px 12px", borderRadius: 5,
    background: "rgba(239,68,68,0.12)", border: "1px solid var(--red)",
    color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 11,
    fontWeight: 700, letterSpacing: "0.06em", cursor: "pointer",
    transition: "all 0.15s", textAlign: "center" as const,
  },
  bypassProgress: {
    marginBottom: 14, padding: "10px 14px",
    background: "rgba(239,68,68,0.06)", border: "1px solid var(--red)", borderRadius: 6,
  },
  bypassProgressHeader: { display: "flex", justifyContent: "space-between", marginBottom: 8 },
  progressBar: { height: 4, background: "var(--bg-surface)", borderRadius: 2, overflow: "hidden" },
  progressFill: { height: "100%", borderRadius: 2, transition: "width 0.3s ease", boxShadow: "0 0 8px var(--red)" },
  results: { flex: 1, minWidth: 0 },
  toolbar: { display: "flex", gap: 10, alignItems: "center", marginBottom: 14, flexWrap: "wrap" as const },
  searchBox: {
    flex: 1, minWidth: 180, display: "flex", alignItems: "center",
    background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 5, padding: "0 12px", gap: 8,
  },
  searchIcon: { color: "var(--text-muted)", fontSize: 16 },
  searchInput: {
    flex: 1, background: "transparent", border: "none", outline: "none",
    color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: 12, padding: "9px 0",
  },
  clearBtn: { background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: 11, padding: 2 },
  badge: { display: "flex", alignItems: "center", gap: 6, padding: "6px 12px", borderRadius: 4, fontFamily: "var(--font-mono)", fontSize: 11, whiteSpace: "nowrap" as const },
  badgeDot: { width: 6, height: 6, borderRadius: "50%", flexShrink: 0 },
  runBtn: {
    background: "var(--cyan)", color: "var(--bg-base)", border: "none", borderRadius: 5,
    padding: "9px 16px", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700,
    letterSpacing: "0.08em", whiteSpace: "nowrap" as const, transition: "opacity 0.15s",
  },
  statsRow: {
    display: "flex", alignItems: "center", gap: 20, padding: "12px 16px",
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, marginBottom: 14, flexWrap: "wrap" as const,
  },
  stat: { display: "flex", alignItems: "baseline", gap: 8 },
  statNum: { fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 700, color: "var(--cyan)" },
  statLabel: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
  statDivider: { width: 1, height: 24, background: "var(--border)" },
  tabRow: { display: "flex", gap: 2, borderBottom: "1px solid var(--border)", marginBottom: 12 },
  tabBtn: {
    padding: "8px 16px", background: "transparent", border: "none",
    borderBottom: "2px solid transparent", cursor: "pointer",
    fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)",
    letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: 8, transition: "all 0.15s",
  },
  tabBtnActive: { color: "var(--text-primary)", borderBottomColor: "var(--cyan)" },
  tabCount: { padding: "1px 6px", borderRadius: 3, fontSize: 9, background: "var(--bg-hover)", color: "var(--text-muted)" },
  sourceRow: { display: "flex", gap: 2, marginBottom: 12 },
  srcBtn: {
    padding: "6px 12px", background: "transparent", border: "none",
    cursor: "pointer", fontFamily: "var(--font-mono)", fontSize: 10,
    letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: 6, transition: "all 0.15s",
  },
  srcCount: { padding: "1px 5px", borderRadius: 3, fontSize: 9, background: "var(--bg-hover)", color: "var(--text-muted)" },
  errorBox: {
    display: "flex", alignItems: "center", gap: 10, padding: "12px 16px",
    background: "rgba(239,68,68,0.08)", border: "1px solid var(--red)",
    borderRadius: 6, color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 14,
  },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", padding: "64px 0", gap: 8 },
  emptyIcon: { fontSize: 32, color: "var(--border-bright)", marginBottom: 8 },
  emptyText: { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-muted)" },
  emptyHint: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", opacity: 0.6 },
  tableWrap: { border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" },
  table: { width: "100%", borderCollapse: "collapse" },
  th: {
    padding: "10px 14px", background: "var(--bg-surface)", borderBottom: "1px solid var(--border)",
    fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
    color: "var(--text-muted)", letterSpacing: "0.12em", textAlign: "left" as const,
  },
  td: { padding: "9px 14px", borderBottom: "1px solid var(--border)", fontFamily: "var(--font-mono)", fontSize: 11 },
};
