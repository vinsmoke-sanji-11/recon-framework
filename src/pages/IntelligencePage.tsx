import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

type Severity = "critical" | "high" | "medium" | "low" | "info";

type Finding = {
  type:         string;
  severity:     Severity;
  title:        string;
  evidence:     string;
  url:          string;
  source_phase: string;
  secret_type?: string;
  matched_params?: string[];
  endpoints?:   string[];
  cve_hint?:    string;
  service?:     string;
  header?:      string;
  missing_flags?: string[];
  bucket?:      string;
  public?:      boolean;
};

type IntelStatus = {
  status:   "not_started" | "running" | "done" | "error";
  findings: number | Finding[];
  critical?: number;
  high?:     number;
  medium?:   number;
  low?:      number;
  info?:     number;
  error?:    string;
  totalFiltered?: number;
};

const SEV_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#6b7280",
  info:     "#3b82f6",
};

const SEV_BG: Record<Severity, string> = {
  critical: "rgba(239,68,68,0.12)",
  high:     "rgba(249,115,22,0.12)",
  medium:   "rgba(234,179,8,0.12)",
  low:      "rgba(107,114,128,0.12)",
  info:     "rgba(59,130,246,0.12)",
};

const SOURCE_LABELS: Record<string, string> = {
  js_analysis:       "JS",
  param_analysis:    "Params",
  header_analysis:   "Headers",
  port_intel:        "Ports",
  confidential_intel:"Confidential",
  takeover_check:    "Takeover",
};

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  error:       "var(--red)",
  not_started: "var(--text-muted)",
};

const MODULES = [
  { id: "js",           label: "JS Analysis",        desc: "Secrets, endpoints, S3 in JS files" },
  { id: "params",       label: "Param Analysis",      desc: "SQLi, XSS, SSRF, IDOR, redirect" },
  { id: "headers",      label: "Header Analysis",     desc: "Missing headers, version disclosure" },
  { id: "ports",        label: "Port Intelligence",   desc: "Admin panels, unauth services, CVEs" },
  { id: "confidential", label: "Confidential Intel",  desc: ".env creds, .git source, backup files" },
  { id: "takeover",     label: "Subdomain Takeover",  desc: "Dangling CNAME takeover detection" },
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 100;

export default function IntelligencePage() {
  const [targets, setTargets]     = useState<string[]>([]);
  const [selected, setSelected]   = useState("");
  const [data, setData]           = useState<IntelStatus | null>(null);
  const [findings, setFindings]   = useState<Finding[]>([]);
  const [loading, setLoading]     = useState(false);
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const [search, setSearch]       = useState("");
  const [page, setPage]           = useState(0);
  const [expanded, setExpanded]   = useState<Set<number>>(new Set());
  const [modules, setModules]     = useState<Record<string, boolean>>({
    js: true, params: true, headers: true, ports: true, confidential: true, takeover: true,
  });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadTargets();
    return () => stopPolling();
  }, []);

  const loadTargets = async () => {
    const res = await axios.get(`${API}/targets`);
    setTargets(res.data || []);
  };

  const fetchFindings = async (target: string, sev = "", pg = 0) => {
    const res = await axios.get(`${API}/intelligence/${target}`, {
      params: { severity: sev === "all" ? "" : sev, page: pg, limit: PAGE_SIZE },
    });
    setData(res.data);
    setFindings(res.data.findings || []);
    return res.data;
  };

  const selectTarget = async (target: string) => {
    stopPolling();
    setSelected(target);
    setData(null);
    setFindings([]);
    setSearch("");
    setSevFilter("all");
    setPage(0);
    setExpanded(new Set());
    const d = await fetchFindings(target, "all", 0);
    if (d.status === "running") startPolling(target);
  };

  const runScan = async () => {
    if (!selected) return;
    setLoading(true);
    setFindings([]);
    setData(prev => prev ? { ...prev, status: "running", findings: [] } : { status: "running", findings: [] });
    await axios.post(`${API}/intelligence/${selected}`, modules);
    startPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const d = await fetchFindings(target, sevFilter === "all" ? "" : sevFilter, page);
      if (d.status !== "running") { stopPolling(); setLoading(false); }
    }, 4000);
  };

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const toggleExpand = (i: number) => {
    setExpanded(prev => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n; });
  };

  const toggleModule = (id: string) => {
    setModules(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const isRunning = loading || data?.status === "running";

  const filtered = findings.filter(f => {
    if (search && !f.title.toLowerCase().includes(search.toLowerCase()) &&
        !f.url.toLowerCase().includes(search.toLowerCase()) &&
        !f.evidence.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const totalPages = Math.ceil((data?.totalFiltered || filtered.length) / PAGE_SIZE);

  const enabledCount = Object.values(modules).filter(Boolean).length;

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 09</div>
          <h1 style={s.title}>Intelligence Engine</h1>
        </div>
        {data && data.status !== "not_started" && (
          <div style={s.sevBadges}>
            {SEVERITIES.map(sev => {
              const count = (data as unknown as Record<string, number>)[sev] || 0;
              if (!count) return null;
              return (
                <div
                  key={sev}
                  style={{
                    ...s.sevBadge,
                    background: SEV_BG[sev],
                    border: `1px solid ${SEV_COLOR[sev]}`,
                    cursor: "pointer",
                    opacity: sevFilter !== "all" && sevFilter !== sev ? 0.4 : 1,
                  }}
                  onClick={() => { setSevFilter(sevFilter === sev ? "all" : sev); setPage(0); fetchFindings(selected, sevFilter === sev ? "" : sev, 0); }}
                >
                  <span style={{ color: SEV_COLOR[sev], fontWeight: 700, fontSize: 18 }}>{count}</span>
                  <span style={{ color: SEV_COLOR[sev], fontSize: 9, letterSpacing: "0.1em" }}>{sev.toUpperCase()}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div style={s.layout}>
        {/* Sidebar */}
        <div style={s.sidebarCol}>
          <div style={s.listLabel}>TARGETS</div>
          {targets.map(t => (
            <button key={t} onClick={() => selectTarget(t)}
              style={{ ...s.targetBtn, ...(selected === t ? s.targetBtnActive : {}) }}>
              <span style={s.targetDot} />{t}
            </button>
          ))}

          {selected && (
            <>
              <div style={{ ...s.listLabel, marginTop: 24 }}>
                MODULES
                <span style={{ marginLeft: 8, color: "var(--cyan)" }}>({enabledCount}/6)</span>
              </div>
              {MODULES.map(mod => (
                <div key={mod.id} style={s.moduleRow}>
                  <div
                    style={{ ...s.toggleSwitch, background: modules[mod.id] ? "var(--cyan)" : "var(--border)" }}
                    onClick={() => toggleModule(mod.id)}
                  >
                    <div style={{ ...s.toggleKnob, left: modules[mod.id] ? 14 : 2 }} />
                  </div>
                  <div style={s.moduleInfo}>
                    <div style={{ ...s.moduleLabel, color: modules[mod.id] ? "var(--text-primary)" : "var(--text-muted)" }}>
                      {mod.label}
                    </div>
                    <div style={s.moduleDesc}>{mod.desc}</div>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>

        {/* Results */}
        <div style={s.results}>
          {!selected ? (
            <div style={s.empty}>
              <div style={s.emptyIcon}>◎</div>
              <div style={s.emptyText}>Select a target to run intelligence analysis</div>
              <div style={s.emptyHint}>JS secrets · Vuln params · Headers · Ports · Takeover detection</div>
            </div>
          ) : (
            <>
              {/* Toolbar */}
              <div style={s.toolbar}>
                <div style={s.searchBox}>
                  <span style={s.searchIcon}>⌕</span>
                  <input value={search} onChange={e => setSearch(e.target.value)}
                    placeholder="Search findings..." style={s.searchInput} spellCheck={false} />
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
                <button onClick={runScan} disabled={isRunning || enabledCount === 0}
                  style={{ ...s.runBtn, opacity: (isRunning || enabledCount === 0) ? 0.45 : 1,
                    cursor: (isRunning || enabledCount === 0) ? "not-allowed" : "pointer" }}>
                  {isRunning ? "ANALYZING..." : "RUN ANALYSIS"}
                </button>
              </div>

              {/* Severity filter tabs */}
              {data && data.status !== "not_started" && (
                <div style={s.sevRow}>
                  <button onClick={() => { setSevFilter("all"); setPage(0); fetchFindings(selected, "", 0); }}
                    style={{ ...s.sevTab, color: sevFilter === "all" ? "var(--text-primary)" : "var(--text-muted)",
                      borderBottom: sevFilter === "all" ? "2px solid var(--cyan)" : "2px solid transparent" }}>
                    ALL
                    <span style={s.sevCount}>{Array.isArray(data.findings) ? (data.findings as Finding[]).length : data.findings}</span>
                  </button>
                  {SEVERITIES.map(sev => {
                    const count = (data as unknown as Record<string, number>)[sev] || 0;
                    if (!count) return null;
                    return (
                      <button key={sev} onClick={() => { setSevFilter(sev); setPage(0); fetchFindings(selected, sev, 0); }}
                        style={{ ...s.sevTab,
                          color: sevFilter === sev ? SEV_COLOR[sev] : "var(--text-muted)",
                          borderBottom: sevFilter === sev ? `2px solid ${SEV_COLOR[sev]}` : "2px solid transparent" }}>
                        {sev.toUpperCase()}
                        <span style={{ ...s.sevCount, background: SEV_BG[sev], color: SEV_COLOR[sev] }}>{count}</span>
                      </button>
                    );
                  })}
                </div>
              )}

              {/* Error */}
              {data?.status === "error" && data.error && (
                <div style={s.errorBox}><span>✕</span> {data.error}</div>
              )}

              {/* Not started */}
              {(!data || data.status === "not_started") && !loading && (
                <div style={s.empty}>
                  <div style={s.emptyText}>Toggle modules and click "Run Analysis"</div>
                  <div style={s.emptyHint}>Each module analyses data from previous phases</div>
                </div>
              )}

              {/* Findings list */}
              {filtered.length > 0 && (
                <>
                  <div style={s.findingsList}>
                    {filtered.map((f, i) => {
                      const isExp = expanded.has(i);
                      return (
                        <div key={i} className="animate-in" style={{
                          ...s.findingCard,
                          borderLeft: `3px solid ${SEV_COLOR[f.severity]}`,
                          background: isExp ? "var(--bg-surface)" : "var(--bg-panel)",
                        }}>
                          <div style={s.findingHeader} onClick={() => toggleExpand(i)}>
                            <div style={s.findingLeft}>
                              <span style={{
                                ...s.sevPill,
                                background: SEV_BG[f.severity],
                                color: SEV_COLOR[f.severity],
                                border: `1px solid ${SEV_COLOR[f.severity]}44`,
                              }}>
                                {f.severity.toUpperCase()}
                              </span>
                              <span style={s.findingTitle}>{f.title}</span>
                            </div>
                            <div style={s.findingRight}>
                              <span style={s.sourceTag}>
                                {SOURCE_LABELS[f.source_phase] || f.source_phase}
                              </span>
                              <span style={s.expandArrow}>{isExp ? "▴" : "▾"}</span>
                            </div>
                          </div>

                          {/* Evidence preview */}
                          <div style={s.evidencePreview}>
                            <span style={s.evidenceText}>{f.evidence}</span>
                          </div>

                          {/* Expanded detail */}
                          {isExp && (
                            <div style={s.expandedBody}>
                              <div style={s.detailGrid}>
                                <div style={s.detailRow}>
                                  <span style={s.dk}>URL</span>
                                  <a href={f.url} target="_blank" rel="noopener noreferrer"
                                    style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--cyan)", textDecoration: "none", wordBreak: "break-all" as const }}>
                                    {f.url}
                                  </a>
                                </div>
                                <div style={s.detailRow}>
                                  <span style={s.dk}>Type</span>
                                  <span style={s.dv}>{f.type}</span>
                                </div>
                                <div style={s.detailRow}>
                                  <span style={s.dk}>Source</span>
                                  <span style={s.dv}>{f.source_phase}</span>
                                </div>
                                {f.secret_type && (
                                  <div style={s.detailRow}>
                                    <span style={s.dk}>Secret type</span>
                                    <span style={{ ...s.dv, color: SEV_COLOR[f.severity] }}>{f.secret_type}</span>
                                  </div>
                                )}
                                {f.cve_hint && (
                                  <div style={s.detailRow}>
                                    <span style={s.dk}>CVE hint</span>
                                    <span style={{ ...s.dv, color: "var(--orange)" }}>{f.cve_hint}</span>
                                  </div>
                                )}
                                {f.matched_params && (
                                  <div style={s.detailRow}>
                                    <span style={s.dk}>Params</span>
                                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" as const }}>
                                      {f.matched_params.map((p, j) => (
                                        <span key={j} style={s.paramChip}>{p}</span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {f.endpoints && f.endpoints.length > 0 && (
                                  <div style={s.detailRow}>
                                    <span style={s.dk}>Endpoints</span>
                                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" as const }}>
                                      {f.endpoints.slice(0, 20).map((e, j) => (
                                        <span key={j} style={s.paramChip}>{e}</span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {f.missing_flags && (
                                  <div style={s.detailRow}>
                                    <span style={s.dk}>Missing</span>
                                    <span style={{ ...s.dv, color: "var(--amber)" }}>{f.missing_flags.join(', ')}</span>
                                  </div>
                                )}
                                {f.bucket && (
                                  <div style={s.detailRow}>
                                    <span style={s.dk}>Bucket</span>
                                    <span style={{ ...s.dv, color: f.public ? "var(--red)" : "var(--amber)" }}>
                                      {f.bucket} {f.public ? "(PUBLIC)" : "(private)"}
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div style={s.pagination}>
                      <button
                        onClick={() => { setPage(p => { const np = Math.max(0, p-1); fetchFindings(selected, sevFilter === "all" ? "" : sevFilter, np); return np; }); }}
                        disabled={page === 0}
                        style={{ ...s.pageBtn, opacity: page === 0 ? 0.3 : 1 }}
                      >← PREV</button>
                      <span style={s.pageInfo}>{page+1} / {totalPages}</span>
                      <button
                        onClick={() => { setPage(p => { const np = Math.min(totalPages-1, p+1); fetchFindings(selected, sevFilter === "all" ? "" : sevFilter, np); return np; }); }}
                        disabled={page >= totalPages-1}
                        style={{ ...s.pageBtn, opacity: page >= totalPages-1 ? 0.3 : 1 }}
                      >NEXT →</button>
                    </div>
                  )}
                </>
              )}

              {data?.status === "done" && filtered.length === 0 && (
                <div style={s.empty}>
                  <div style={s.emptyText}>{search ? "No findings match search" : "No findings detected"}</div>
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
  sevBadges: { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" as const },
  sevBadge: {
    display: "flex", flexDirection: "column" as const, alignItems: "center",
    padding: "6px 12px", borderRadius: 6, minWidth: 52, transition: "opacity 0.15s", cursor: "pointer",
    fontFamily: "var(--font-mono)",
  },
  layout: { display: "flex", gap: 20, alignItems: "flex-start" },
  sidebarCol: { width: 210, flexShrink: 0, display: "flex", flexDirection: "column", gap: 4 },
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
  moduleRow: { display: "flex", alignItems: "flex-start", gap: 10, padding: "6px 4px" },
  toggleSwitch: { position: "relative" as const, width: 28, height: 16, borderRadius: 8, cursor: "pointer", flexShrink: 0, transition: "background 0.2s", marginTop: 2 },
  toggleKnob: { position: "absolute" as const, top: 2, width: 12, height: 12, borderRadius: "50%", background: "white", transition: "left 0.2s" },
  moduleInfo: { flex: 1 },
  moduleLabel: { fontFamily: "var(--font-mono)", fontSize: 11, marginBottom: 2, transition: "color 0.15s" },
  moduleDesc: { fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", lineHeight: 1.4 },
  results: { flex: 1, minWidth: 0 },
  toolbar: { display: "flex", gap: 10, alignItems: "center", marginBottom: 14, flexWrap: "wrap" as const },
  searchBox: {
    flex: 1, minWidth: 180, display: "flex", alignItems: "center",
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 5, padding: "0 12px", gap: 8,
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
  sevRow: { display: "flex", gap: 2, borderBottom: "1px solid var(--border)", marginBottom: 14, flexWrap: "wrap" as const },
  sevTab: {
    padding: "8px 14px", background: "transparent", border: "none",
    cursor: "pointer", fontFamily: "var(--font-mono)", fontSize: 10,
    letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: 6, transition: "all 0.15s",
  },
  sevCount: { padding: "1px 5px", borderRadius: 3, fontSize: 9, background: "var(--bg-hover)", color: "var(--text-muted)" },
  errorBox: {
    display: "flex", alignItems: "center", gap: 10, padding: "12px 16px",
    background: "rgba(239,68,68,0.08)", border: "1px solid var(--red)",
    borderRadius: 6, color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 14,
  },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", padding: "64px 0", gap: 8 },
  emptyIcon: { fontSize: 32, color: "var(--border-bright)", marginBottom: 8 },
  emptyText: { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-muted)" },
  emptyHint: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", opacity: 0.6 },
  findingsList: { display: "flex", flexDirection: "column", gap: 6 },
  findingCard: {
    borderRadius: 6, border: "1px solid var(--border)", overflow: "hidden",
    transition: "background 0.15s",
  },
  findingHeader: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "10px 14px", cursor: "pointer",
  },
  findingLeft: { display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0 },
  sevPill: {
    padding: "2px 8px", borderRadius: 3, fontSize: 9,
    fontFamily: "var(--font-mono)", fontWeight: 700, letterSpacing: "0.1em", flexShrink: 0,
  },
  findingTitle: {
    fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-primary)",
    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const,
  },
  findingRight: { display: "flex", alignItems: "center", gap: 10, flexShrink: 0 },
  sourceTag: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  expandArrow: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  evidencePreview: {
    padding: "6px 14px 8px",
    borderTop: "1px solid var(--border)",
    background: "var(--bg-surface)",
  },
  evidenceText: {
    fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)",
    wordBreak: "break-all" as const, whiteSpace: "pre-wrap" as const,
  },
  expandedBody: { padding: "12px 14px", borderTop: "1px solid var(--border)" },
  detailGrid: { display: "flex", flexDirection: "column", gap: 8 },
  detailRow: { display: "flex", gap: 16, alignItems: "flex-start" },
  dk: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", width: 90, flexShrink: 0, paddingTop: 1 },
  dv: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)", wordBreak: "break-all" as const },
  paramChip: {
    padding: "2px 7px", borderRadius: 3, fontSize: 10,
    fontFamily: "var(--font-mono)", color: "var(--cyan)",
    background: "var(--cyan-glow)", border: "1px solid var(--cyan)44",
  },
  pagination: { display: "flex", alignItems: "center", justifyContent: "center", gap: 16, padding: "16px 0" },
  pageBtn: {
    background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 4,
    padding: "6px 14px", fontFamily: "var(--font-mono)", fontSize: 11,
    color: "var(--text-secondary)", cursor: "pointer", letterSpacing: "0.06em",
  },
  pageInfo: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
};
