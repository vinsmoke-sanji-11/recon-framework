import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

type Severity = "critical" | "high" | "medium" | "low" | "info";

type Finding = {
  id:             string;
  severity:       Severity;
  type:           string;
  title:          string;
  evidence:       string;
  url:            string;
  source_phase:   string;
  template_id:    string;
  tags:           string;
  reference:      string;
  recommendation: string;
  ts:             string;
};

type NucleiStatus = {
  status:       "not_started" | "running" | "done" | "failed";
  total?:       number;
  critical?:    number;
  high?:        number;
  medium?:      number;
  low?:         number;
  info?:        number;
  hosts?:       number;
  error?:       string;
  startedAt?:   string;
  completedAt?: string;
  findings:     Finding[];
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

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  failed:      "var(--red)",
  not_started: "var(--text-muted)",
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const TAG_PRESETS = [
  { label: "CVEs",          value: "cve" },
  { label: "Misconfig",     value: "misconfig" },
  { label: "Exposure",      value: "exposure" },
  { label: "Default Login", value: "default-login" },
  { label: "Takeover",      value: "takeover" },
  { label: "Panels",        value: "panel" },
  { label: "Tech Detect",   value: "tech" },
];

export default function NucleiPage() {
  const [targets, setTargets]         = useState<string[]>([]);
  const [selected, setSelected]       = useState("");
  const [data, setData]               = useState<NucleiStatus | null>(null);
  const [findings, setFindings]       = useState<Finding[]>([]);
  const [loading, setLoading]         = useState(false);
  const [sevFilter, setSevFilter]     = useState<Severity | "all">("all");
  const [search, setSearch]           = useState("");
  const [expanded, setExpanded]       = useState<Set<number>>(new Set());
  const [selSeverities, setSelSeverities] = useState<Set<Severity>>(
    new Set(["critical", "high", "medium", "low", "info"])
  );
  const [selTags, setSelTags]         = useState<Set<string>>(new Set());
  const [rateLimit, setRateLimit]     = useState(150);
  const [concurrency, setConcurrency] = useState(25);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadTargets();
    return () => stopPolling();
  }, []);

  const loadTargets = async () => {
    const res = await axios.get(`${API}/targets`);
    setTargets(res.data || []);
  };

  const fetchStatus = async (target: string) => {
    const res = await axios.get(`${API}/nuclei/${target}`);
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
    setExpanded(new Set());
    const d = await fetchStatus(target);
    if (d.status === "running") startPolling(target);
  };

  const runScan = async () => {
    if (!selected) return;
    setLoading(true);
    setFindings([]);
    setData({ status: "running", findings: [], total: 0 });
    await axios.post(`${API}/nuclei/${selected}`, {
      severity:    [...selSeverities],
      tags:        [...selTags],
      rateLimit,
      concurrency,
    });
    startPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const d = await fetchStatus(target);
      if (d.status !== "running") { stopPolling(); setLoading(false); }
    }, 4000);
  };

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const toggleSeverity = (sev: Severity) => {
    setSelSeverities(prev => { const n = new Set(prev); n.has(sev) ? n.delete(sev) : n.add(sev); return n; });
  };

  const toggleTag = (tag: string) => {
    setSelTags(prev => { const n = new Set(prev); n.has(tag) ? n.delete(tag) : n.add(tag); return n; });
  };

  const toggleExpand = (i: number) => {
    setExpanded(prev => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n; });
  };

  const isRunning = loading || data?.status === "running";

  const filtered = findings.filter(f => {
    if (sevFilter !== "all" && f.severity !== sevFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!f.title.toLowerCase().includes(q) &&
          !f.url.toLowerCase().includes(q) &&
          !f.template_id.toLowerCase().includes(q) &&
          !f.tags.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 10</div>
          <h1 style={s.title}>Nuclei Scanner</h1>
        </div>
        {data && data.status !== "not_started" && (
          <div style={s.sevBadges}>
            {SEVERITIES.map(sev => {
              const count = (data as unknown as Record<string, number>)[sev] || 0;
              if (!count) return null;
              return (
                <div key={sev} onClick={() => setSevFilter(sevFilter === sev ? "all" : sev)}
                  style={{
                    ...s.sevBadge,
                    background: SEV_BG[sev],
                    border: `1px solid ${SEV_COLOR[sev]}`,
                    cursor: "pointer",
                    opacity: sevFilter !== "all" && sevFilter !== sev ? 0.4 : 1,
                  }}>
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
              <div style={{ ...s.listLabel, marginTop: 24 }}>SEVERITY</div>
              <div style={s.sevToggles}>
                {SEVERITIES.map(sev => (
                  <div key={sev} onClick={() => toggleSeverity(sev)}
                    style={{ ...s.sevToggleRow, opacity: selSeverities.has(sev) ? 1 : 0.35 }}>
                    <div style={{
                      ...s.sevDot,
                      background: selSeverities.has(sev) ? SEV_COLOR[sev] : "var(--border)",
                      boxShadow: selSeverities.has(sev) ? `0 0 6px ${SEV_COLOR[sev]}` : "none",
                    }} />
                    <span style={{ ...s.sevToggleLabel, color: selSeverities.has(sev) ? SEV_COLOR[sev] : "var(--text-muted)" }}>
                      {sev.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>

              <div style={{ ...s.listLabel, marginTop: 20 }}>TAGS (OPTIONAL)</div>
              <div style={s.tagGrid}>
                {TAG_PRESETS.map(tag => (
                  <div key={tag.value} onClick={() => toggleTag(tag.value)}
                    style={{
                      ...s.tagChip,
                      background: selTags.has(tag.value) ? "var(--cyan-glow)" : "var(--bg-panel)",
                      border: `1px solid ${selTags.has(tag.value) ? "var(--cyan)" : "var(--border)"}`,
                      color: selTags.has(tag.value) ? "var(--cyan)" : "var(--text-muted)",
                    }}>
                    {tag.label}
                  </div>
                ))}
              </div>

              <div style={{ ...s.listLabel, marginTop: 20 }}>OPTIONS</div>
              <div style={s.optionRow}>
                <span style={s.optLabel}>Rate limit</span>
                <input type="number" value={rateLimit}
                  onChange={e => setRateLimit(Number(e.target.value))}
                  style={s.optInput} min={10} max={500} />
              </div>
              <div style={s.optionRow}>
                <span style={s.optLabel}>Concurrency</span>
                <input type="number" value={concurrency}
                  onChange={e => setConcurrency(Number(e.target.value))}
                  style={s.optInput} min={1} max={100} />
              </div>

              {data?.hosts !== undefined && (
                <div style={s.hostsInfo}>
                  <span style={s.hostsNum}>{data.hosts}</span>
                  <span style={s.hostsLabel}>hosts in scope</span>
                </div>
              )}
            </>
          )}
        </div>

        {/* Results */}
        <div style={s.results}>
          {!selected ? (
            <div style={s.empty}>
              <div style={s.emptyIcon}>⬡</div>
              <div style={s.emptyText}>Select a target to run Nuclei</div>
              <div style={s.emptyHint}>CVEs · Misconfigs · Exposures · Default logins · Takeovers</div>
            </div>
          ) : (
            <>
              <div style={s.toolbar}>
                <div style={s.searchBox}>
                  <span style={s.searchIcon}>⌕</span>
                  <input value={search} onChange={e => setSearch(e.target.value)}
                    placeholder="Search findings, templates, tags..."
                    style={s.searchInput} spellCheck={false} />
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
                    {isRunning ? `running · ${data.total || 0} found` : data.status}
                  </div>
                )}
                <button onClick={runScan} disabled={isRunning || selSeverities.size === 0}
                  style={{
                    ...s.runBtn,
                    opacity: (isRunning || selSeverities.size === 0) ? 0.45 : 1,
                    cursor: (isRunning || selSeverities.size === 0) ? "not-allowed" : "pointer",
                  }}>
                  {isRunning ? "SCANNING..." : "RUN NUCLEI"}
                </button>
              </div>

              {data && data.status !== "not_started" && (
                <div style={s.sevRow}>
                  <button onClick={() => setSevFilter("all")}
                    style={{ ...s.sevTab, color: sevFilter === "all" ? "var(--text-primary)" : "var(--text-muted)", borderBottom: sevFilter === "all" ? "2px solid var(--cyan)" : "2px solid transparent" }}>
                    ALL <span style={s.sevCount}>{data.total || 0}</span>
                  </button>
                  {SEVERITIES.map(sev => {
                    const count = (data as unknown as Record<string, number>)[sev] || 0;
                    if (!count) return null;
                    return (
                      <button key={sev} onClick={() => setSevFilter(sev)}
                        style={{ ...s.sevTab, color: sevFilter === sev ? SEV_COLOR[sev] : "var(--text-muted)", borderBottom: sevFilter === sev ? `2px solid ${SEV_COLOR[sev]}` : "2px solid transparent" }}>
                        {sev.toUpperCase()} <span style={{ ...s.sevCount, background: SEV_BG[sev], color: SEV_COLOR[sev] }}>{count}</span>
                      </button>
                    );
                  })}
                </div>
              )}

              {data?.status === "failed" && data.error && (
                <div style={s.errorBox}><span>✕</span> {data.error}</div>
              )}

              {(!data || data.status === "not_started") && !loading && (
                <div style={s.empty}>
                  <div style={s.emptyText}>Configure options and click "Run Nuclei"</div>
                  <div style={s.emptyHint}>Requires live hosts from Phase 03</div>
                </div>
              )}

              {filtered.length > 0 && (
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
                            <span style={{ ...s.sevPill, background: SEV_BG[f.severity], color: SEV_COLOR[f.severity], border: `1px solid ${SEV_COLOR[f.severity]}44` }}>
                              {f.severity.toUpperCase()}
                            </span>
                            <span style={s.findingTitle}>{f.title}</span>
                          </div>
                          <div style={s.findingRight}>
                            <span style={s.templateTag}>{f.template_id}</span>
                            <span style={s.expandArrow}>{isExp ? "▴" : "▾"}</span>
                          </div>
                        </div>

                        <div style={s.evidencePreview}>
                          <span style={s.evidenceText}>{f.url}</span>
                        </div>

                        {isExp && (
                          <div style={s.expandedBody}>
                            <div style={s.detailGrid}>
                              <div style={s.detailRow}>
                                <span style={s.dk}>Matched</span>
                                <a href={f.url} target="_blank" rel="noopener noreferrer"
                                  style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--cyan)", textDecoration: "none", wordBreak: "break-all" as const }}>
                                  {f.url}
                                </a>
                              </div>
                              <div style={s.detailRow}>
                                <span style={s.dk}>Template</span>
                                <span style={{ ...s.dv, color: "var(--cyan)" }}>{f.template_id}</span>
                              </div>
                              {f.tags && (
                                <div style={s.detailRow}>
                                  <span style={s.dk}>Tags</span>
                                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" as const }}>
                                    {f.tags.split(",").map((tag, j) => (
                                      <span key={j} style={s.tagChipSmall}>{tag.trim()}</span>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {f.evidence && (
                                <div style={s.detailRow}>
                                  <span style={s.dk}>Evidence</span>
                                  <pre style={s.evidencePre}>{f.evidence}</pre>
                                </div>
                              )}
                              {f.recommendation && (
                                <div style={s.detailRow}>
                                  <span style={s.dk}>Fix</span>
                                  <span style={s.dv}>{f.recommendation}</span>
                                </div>
                              )}
                              {f.reference && (
                                <div style={s.detailRow}>
                                  <span style={s.dk}>Reference</span>
                                  <a href={f.reference} target="_blank" rel="noopener noreferrer"
                                    style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--cyan)", textDecoration: "none", wordBreak: "break-all" as const }}>
                                    {f.reference}
                                  </a>
                                </div>
                              )}
                              <div style={s.detailRow}>
                                <span style={s.dk}>Detected</span>
                                <span style={s.dv}>{new Date(f.ts).toLocaleString()}</span>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {data?.status === "done" && filtered.length === 0 && (
                <div style={s.empty}>
                  <div style={s.emptyText}>{search ? "No findings match search" : "No findings detected"}</div>
                  {!search && <div style={s.emptyHint}>Try broader severity levels or remove tag filters</div>}
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
  header:     { display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 28 },
  phase:      { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--cyan)", letterSpacing: "0.2em", marginBottom: 6 },
  title:      { fontSize: 26, fontWeight: 600, letterSpacing: "-0.02em" },
  sevBadges:  { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" as const },
  sevBadge:   { display: "flex", flexDirection: "column" as const, alignItems: "center", padding: "6px 12px", borderRadius: 6, minWidth: 52, transition: "opacity 0.15s", fontFamily: "var(--font-mono)" },
  layout:     { display: "flex", gap: 20, alignItems: "flex-start" },
  sidebarCol: { width: 210, flexShrink: 0, display: "flex", flexDirection: "column", gap: 4 },
  listLabel:  { fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.2em", marginBottom: 6, paddingLeft: 4 },
  targetBtn:  { display: "flex", alignItems: "center", gap: 8, padding: "9px 11px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 5, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", fontSize: 11, cursor: "pointer", textAlign: "left" as const, width: "100%", wordBreak: "break-all" as const, transition: "all 0.15s" },
  targetBtnActive: { border: "1px solid var(--cyan)", color: "var(--cyan)", background: "var(--cyan-glow)" },
  targetDot:  { display: "inline-block", width: 5, height: 5, borderRadius: "50%", background: "currentColor", flexShrink: 0 },
  sevToggles: { display: "flex", flexDirection: "column" as const, gap: 2 },
  sevToggleRow: { display: "flex", alignItems: "center", gap: 9, padding: "6px 6px", cursor: "pointer", borderRadius: 4, transition: "opacity 0.15s" },
  sevDot:     { width: 8, height: 8, borderRadius: "50%", flexShrink: 0, transition: "all 0.15s" },
  sevToggleLabel: { fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.08em", transition: "color 0.15s" },
  tagGrid:    { display: "flex", flexDirection: "column" as const, gap: 4 },
  tagChip:    { padding: "5px 10px", borderRadius: 4, fontSize: 10, fontFamily: "var(--font-mono)", cursor: "pointer", transition: "all 0.15s", textAlign: "center" as const },
  optionRow:  { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, padding: "4px 0" },
  optLabel:   { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  optInput:   { width: 64, background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 4, padding: "4px 8px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-primary)", outline: "none", textAlign: "right" as const },
  hostsInfo:  { display: "flex", flexDirection: "column" as const, alignItems: "center", padding: "12px 0", marginTop: 8, borderTop: "1px solid var(--border)" },
  hostsNum:   { fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 700, color: "var(--cyan)", lineHeight: 1 },
  hostsLabel: { fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", marginTop: 4 },
  results:    { flex: 1, minWidth: 0 },
  toolbar:    { display: "flex", gap: 10, alignItems: "center", marginBottom: 14, flexWrap: "wrap" as const },
  searchBox:  { flex: 1, minWidth: 180, display: "flex", alignItems: "center", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 5, padding: "0 12px", gap: 8 },
  searchIcon: { color: "var(--text-muted)", fontSize: 16 },
  searchInput: { flex: 1, background: "transparent", border: "none", outline: "none", color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: 12, padding: "9px 0" },
  clearBtn:   { background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: 11, padding: 2 },
  badge:      { display: "flex", alignItems: "center", gap: 6, padding: "6px 12px", borderRadius: 4, fontFamily: "var(--font-mono)", fontSize: 11, whiteSpace: "nowrap" as const },
  badgeDot:   { width: 6, height: 6, borderRadius: "50%", flexShrink: 0 },
  runBtn:     { background: "var(--cyan)", color: "var(--bg-base)", border: "none", borderRadius: 5, padding: "9px 16px", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", whiteSpace: "nowrap" as const, transition: "opacity 0.15s" },
  sevRow:     { display: "flex", gap: 2, borderBottom: "1px solid var(--border)", marginBottom: 14, flexWrap: "wrap" as const },
  sevTab:     { padding: "8px 14px", background: "transparent", border: "none", cursor: "pointer", fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: 6, transition: "all 0.15s" },
  sevCount:   { padding: "1px 5px", borderRadius: 3, fontSize: 9, background: "var(--bg-hover)", color: "var(--text-muted)" },
  errorBox:   { display: "flex", alignItems: "center", gap: 10, padding: "12px 16px", background: "rgba(239,68,68,0.08)", border: "1px solid var(--red)", borderRadius: 6, color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 14 },
  empty:      { display: "flex", flexDirection: "column" as const, alignItems: "center", padding: "64px 0", gap: 8 },
  emptyIcon:  { fontSize: 32, color: "var(--border-bright)", marginBottom: 8 },
  emptyText:  { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-muted)" },
  emptyHint:  { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", opacity: 0.6 },
  findingsList: { display: "flex", flexDirection: "column" as const, gap: 6 },
  findingCard: { borderRadius: 6, border: "1px solid var(--border)", overflow: "hidden", transition: "background 0.15s" },
  findingHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", cursor: "pointer" },
  findingLeft: { display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0 },
  sevPill:    { padding: "2px 8px", borderRadius: 3, fontSize: 9, fontFamily: "var(--font-mono)", fontWeight: 700, letterSpacing: "0.1em", flexShrink: 0 },
  findingTitle: { fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const },
  findingRight: { display: "flex", alignItems: "center", gap: 10, flexShrink: 0 },
  templateTag: { fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", background: "var(--bg-surface)", padding: "2px 6px", borderRadius: 3, border: "1px solid var(--border)" },
  expandArrow: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  evidencePreview: { padding: "5px 14px 7px", borderTop: "1px solid var(--border)", background: "var(--bg-surface)" },
  evidenceText: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", wordBreak: "break-all" as const },
  expandedBody: { padding: "12px 14px", borderTop: "1px solid var(--border)" },
  detailGrid: { display: "flex", flexDirection: "column" as const, gap: 8 },
  detailRow:  { display: "flex", gap: 16, alignItems: "flex-start" },
  dk:         { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", width: 80, flexShrink: 0, paddingTop: 1 },
  dv:         { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)", wordBreak: "break-all" as const },
  evidencePre: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-secondary)", background: "var(--bg-base)", padding: "8px 10px", borderRadius: 4, border: "1px solid var(--border)", margin: 0, whiteSpace: "pre-wrap" as const, wordBreak: "break-all" as const, maxHeight: 200, overflowY: "auto" as const },
  tagChipSmall: { padding: "2px 7px", borderRadius: 3, fontSize: 9, fontFamily: "var(--font-mono)", color: "var(--cyan)", background: "var(--cyan-glow)", border: "1px solid var(--cyan)44" },
};
