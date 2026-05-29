import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

type Result = {
  type:          string;
  ip:            string | null;
  hosts:         string[];
  cdn:           string | null;
  behind_cdn:    boolean;
  source:        string;
  confidence:    "high" | "medium" | "low";
  note?:         string;
  sans?:         string[];
  direct_access?: boolean;
  direct_status?: number;
};

type OriginStatus = {
  status:        "not_started" | "running" | "done" | "error";
  totalIPs?:     number;
  behindCDN?:    number;
  directExposed?: number;
  confirmed?:    number;
  cdnBreakdown?: Record<string, number>;
  error?:        string;
  results:       Result[];
};

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  error:       "var(--red)",
  not_started: "var(--text-muted)",
};

const CDN_COLOR: Record<string, string> = {
  cloudflare: "#f6821f",
  akamai:     "#009bde",
  fastly:     "#ff282d",
  sucuri:     "#1a9b6a",
  incapsula:  "#6c3dd4",
};

const CONFIDENCE_COLOR: Record<string, string> = {
  high:   "var(--green)",
  medium: "var(--amber)",
  low:    "var(--text-muted)",
};

const SOURCE_LABEL: Record<string, string> = {
  dns_records:     "DNS",
  subdomain_scan:  "Subdomain",
  mx_record:       "MX Record",
  shodan_internetdb: "Historical",
  tls_certificate: "TLS Cert",
};

type FilterTab = "all" | "direct" | "cdn" | "confirmed";

export default function OriginIPPage() {
  const [targets, setTargets]   = useState<string[]>([]);
  const [selected, setSelected] = useState("");
  const [data, setData]         = useState<OriginStatus | null>(null);
  const [loading, setLoading]   = useState(false);
  const [filter, setFilter]     = useState<FilterTab>("all");
  const [search, setSearch]     = useState("");
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadTargets();
    return () => stopPolling();
  }, []);

  const loadTargets = async () => {
    const res = await axios.get(`${API}/targets`);
    setTargets(res.data || []);
  };

  const selectTarget = async (target: string) => {
    stopPolling();
    setSelected(target);
    setData(null);
    setSearch("");
    setFilter("all");
    setExpanded(new Set());
    const res = await axios.get(`${API}/originip/${target}`);
    setData(res.data);
    if (res.data.status === "running") startPolling(target);
  };

  const runDetection = async () => {
    if (!selected) return;
    setLoading(true);
    setData(prev => prev
      ? { ...prev, status: "running", results: [] }
      : { status: "running", results: [] }
    );
    await axios.post(`${API}/originip/${selected}`);
    startPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const res = await axios.get(`${API}/originip/${target}`);
      setData(res.data);
      if (res.data.status !== "running") {
        stopPolling();
        setLoading(false);
      }
    }, 3000);
  };

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const toggleExpand = (i: number) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });
  };

  const isRunning = loading || data?.status === "running";

  const results = data?.results || [];

  const filtered = results.filter(r => {
    if (filter === "direct"    && r.behind_cdn)      return false;
    if (filter === "cdn"       && !r.behind_cdn)     return false;
    if (filter === "confirmed" && !r.direct_access)  return false;
    if (search) {
      const q = search.toLowerCase();
      if (!(r.ip || "").toLowerCase().includes(q) &&
          !r.hosts.some(h => h.toLowerCase().includes(q)) &&
          !(r.note || "").toLowerCase().includes(q)) return false;
    }
    return true;
  });

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 08</div>
          <h1 style={s.title}>Origin IP Detection</h1>
        </div>
        {data?.totalIPs !== undefined && (
          <div style={{ display: "flex", gap: 24, alignItems: "flex-end" }}>
            <div style={s.countBox}>
              <span style={s.countNum}>{data.totalIPs}</span>
              <span style={s.countLabel}>total IPs</span>
            </div>
            <div style={s.countBox}>
              <span style={{ ...s.countNum, color: "var(--green)" }}>{data.directExposed}</span>
              <span style={s.countLabel}>direct</span>
            </div>
            {(data.confirmed || 0) > 0 && (
              <div style={s.countBox}>
                <span style={{ ...s.countNum, color: "var(--red)" }}>{data.confirmed}</span>
                <span style={s.countLabel}>confirmed</span>
              </div>
            )}
          </div>
        )}
      </div>

      <div style={s.layout}>
        {/* Sidebar */}
        <div style={s.sidebarCol}>
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

          {/* CDN breakdown */}
          {data?.cdnBreakdown && Object.keys(data.cdnBreakdown).length > 0 && (
            <>
              <div style={{ ...s.listLabel, marginTop: 24 }}>CDN DETECTED</div>
              {Object.entries(data.cdnBreakdown).map(([cdn, count]) => (
                <div key={cdn} style={s.cdnRow}>
                  <span style={{
                    width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                    background: CDN_COLOR[cdn] || "var(--text-muted)",
                    display: "inline-block",
                  }} />
                  <span style={s.cdnName}>{cdn}</span>
                  <span style={s.cdnCount}>{count}</span>
                </div>
              ))}
            </>
          )}
        </div>

        {/* Results */}
        <div style={s.results}>
          {!selected ? (
            <div style={s.empty}>
              <div style={s.emptyIcon}>⊕</div>
              <div style={s.emptyText}>Select a target to detect origin IPs</div>
              <div style={s.emptyHint}>Identifies real server IPs behind Cloudflare, Akamai, Fastly and more</div>
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
                    placeholder="Filter by IP or hostname..."
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
                  onClick={runDetection}
                  disabled={isRunning}
                  style={{ ...s.runBtn, opacity: isRunning ? 0.45 : 1, cursor: isRunning ? "not-allowed" : "pointer" }}
                >
                  {isRunning ? "DETECTING..." : "RUN DETECTION"}
                </button>
              </div>

              {/* Stats bar */}
              {data?.totalIPs !== undefined && (
                <div style={s.statsRow}>
                  {[
                    { id: "all",       label: "ALL",       count: results.length,                          color: "var(--text-primary)" },
                    { id: "direct",    label: "DIRECT",    count: results.filter(r => !r.behind_cdn && r.ip).length, color: "var(--green)" },
                    { id: "cdn",       label: "BEHIND CDN", count: results.filter(r => r.behind_cdn).length, color: "var(--orange)" },
                    { id: "confirmed", label: "CONFIRMED", count: results.filter(r => r.direct_access).length, color: "var(--red)" },
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setFilter(tab.id as FilterTab)}
                      style={{
                        ...s.filterTab,
                        color: filter === tab.id ? tab.color : "var(--text-muted)",
                        borderBottom: filter === tab.id ? `2px solid ${tab.color}` : "2px solid transparent",
                      }}
                    >
                      {tab.label}
                      <span style={s.filterCount}>{tab.count}</span>
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
                  <div style={s.emptyText}>Click "Run Detection" to start</div>
                  <div style={s.emptyHint}>Uses DNS records, MX records, historical IPs, TLS certs, and direct probing</div>
                </div>
              )}

              {/* Results list */}
              {filtered.length > 0 && (
                <div style={s.resultList}>
                  {filtered.map((r, i) => {
                    const isExp = expanded.has(i);
                    const isConfirmed = r.direct_access;
                    const isDirect    = !r.behind_cdn && r.ip;

                    return (
                      <div
                        key={i}
                        className="animate-in"
                        style={{
                          ...s.resultCard,
                          borderColor: isConfirmed
                            ? "var(--green)"
                            : isDirect
                            ? "var(--border-bright)"
                            : "var(--border)",
                          background: isConfirmed
                            ? "rgba(16,185,129,0.04)"
                            : "var(--bg-panel)",
                        }}
                      >
                        <div
                          style={s.cardHeader}
                          onClick={() => toggleExpand(i)}
                        >
                          <div style={s.cardLeft}>
                            {/* CDN or direct indicator */}
                            <div style={{
                              width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                              background: r.behind_cdn
                                ? CDN_COLOR[r.cdn || ""] || "var(--orange)"
                                : isConfirmed ? "var(--green)" : "var(--cyan)",
                              boxShadow: isConfirmed ? "0 0 6px var(--green)" : "none",
                            }} />

                            {/* IP */}
                            <span style={s.ipText}>
                              {r.ip || "—"}
                            </span>

                            {/* CDN badge */}
                            {r.cdn && (
                              <span style={{
                                ...s.cdnBadge,
                                background: `${CDN_COLOR[r.cdn] || "var(--orange)"}22`,
                                border: `1px solid ${CDN_COLOR[r.cdn] || "var(--orange)"}`,
                                color: CDN_COLOR[r.cdn] || "var(--orange)",
                              }}>
                                {r.cdn}
                              </span>
                            )}

                            {/* Confirmed badge */}
                            {isConfirmed && (
                              <span style={s.confirmedBadge}>
                                ✓ CONFIRMED {r.direct_status}
                              </span>
                            )}

                            {/* Direct badge */}
                            {isDirect && !isConfirmed && (
                              <span style={s.directBadge}>DIRECT</span>
                            )}
                          </div>

                          <div style={s.cardRight}>
                            {/* Source */}
                            <span style={s.sourceTag}>
                              {SOURCE_LABEL[r.source] || r.source}
                            </span>
                            {/* Confidence */}
                            <span style={{ ...s.confTag, color: CONFIDENCE_COLOR[r.confidence] }}>
                              {r.confidence}
                            </span>
                            <span style={s.expandArrow}>{isExp ? "▴" : "▾"}</span>
                          </div>
                        </div>

                        {/* Hosts preview */}
                        <div style={s.hostsRow}>
                          {r.hosts.slice(0, 4).map((h, j) => (
                            <span key={j} style={s.hostChip}>{h}</span>
                          ))}
                          {r.hosts.length > 4 && (
                            <span style={s.moreChip}>+{r.hosts.length - 4}</span>
                          )}
                        </div>

                        {/* Expanded details */}
                        {isExp && (
                          <div style={s.expandedBody}>
                            <div style={s.detailGrid}>
                              <div style={s.detailRow}>
                                <span style={s.detailKey}>Type</span>
                                <span style={s.detailVal}>{r.type}</span>
                              </div>
                              <div style={s.detailRow}>
                                <span style={s.detailKey}>Source</span>
                                <span style={s.detailVal}>{r.source}</span>
                              </div>
                              <div style={s.detailRow}>
                                <span style={s.detailKey}>Behind CDN</span>
                                <span style={{ ...s.detailVal, color: r.behind_cdn ? "var(--orange)" : "var(--green)" }}>
                                  {r.behind_cdn ? `Yes (${r.cdn})` : "No"}
                                </span>
                              </div>
                              {r.direct_access !== undefined && (
                                <div style={s.detailRow}>
                                  <span style={s.detailKey}>Direct access</span>
                                  <span style={{ ...s.detailVal, color: r.direct_access ? "var(--green)" : "var(--red)" }}>
                                    {r.direct_access ? `Yes — HTTP ${r.direct_status}` : "No"}
                                  </span>
                                </div>
                              )}
                              {r.note && (
                                <div style={s.detailRow}>
                                  <span style={s.detailKey}>Note</span>
                                  <span style={s.detailVal}>{r.note}</span>
                                </div>
                              )}
                            </div>
                            {r.hosts.length > 0 && (
                              <div style={{ marginTop: 10 }}>
                                <div style={s.detailKey}>All hostnames</div>
                                <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 4, marginTop: 4 }}>
                                  {r.hosts.map((h, j) => (
                                    <span key={j} style={s.hostChip}>{h}</span>
                                  ))}
                                </div>
                              </div>
                            )}
                            {r.sans && r.sans.length > 0 && (
                              <div style={{ marginTop: 10 }}>
                                <div style={s.detailKey}>TLS SANs</div>
                                <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 4, marginTop: 4 }}>
                                  {r.sans.map((san, j) => (
                                    <span key={j} style={{ ...s.hostChip, color: "var(--amber)" }}>{san}</span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {data?.status === "done" && filtered.length === 0 && (
                <div style={s.empty}>
                  <div style={s.emptyText}>
                    {search || filter !== "all" ? "No results match filter" : "No IPs found"}
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
  sidebarCol: { width: 190, flexShrink: 0, display: "flex", flexDirection: "column", gap: 4 },
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
  cdnRow: { display: "flex", alignItems: "center", gap: 8, padding: "5px 4px" },
  cdnName: { flex: 1, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)", textTransform: "capitalize" as const },
  cdnCount: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
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
  statsRow: {
    display: "flex", alignItems: "center", gap: 2,
    borderBottom: "1px solid var(--border)", marginBottom: 14,
  },
  filterTab: {
    padding: "8px 14px", background: "transparent", border: "none",
    cursor: "pointer", fontFamily: "var(--font-mono)", fontSize: 10,
    letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: 6,
    transition: "all 0.15s",
  },
  filterCount: {
    padding: "1px 5px", borderRadius: 3, fontSize: 9,
    background: "var(--bg-hover)", color: "var(--text-muted)",
  },
  errorBox: {
    display: "flex", alignItems: "center", gap: 10, padding: "12px 16px",
    background: "rgba(239,68,68,0.08)", border: "1px solid var(--red)",
    borderRadius: 6, color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 14,
  },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", padding: "64px 0", gap: 8 },
  emptyIcon: { fontSize: 32, color: "var(--border-bright)", marginBottom: 8 },
  emptyText: { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-muted)" },
  emptyHint: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", opacity: 0.6 },
  resultList: { display: "flex", flexDirection: "column", gap: 8 },
  resultCard: {
    borderRadius: 6, border: "1px solid var(--border)",
    overflow: "hidden", transition: "border-color 0.15s",
  },
  cardHeader: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "10px 14px", cursor: "pointer", background: "var(--bg-surface)",
  },
  cardLeft: { display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" as const },
  ipText: { fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 700, color: "var(--text-primary)" },
  cdnBadge: {
    padding: "2px 8px", borderRadius: 3, fontSize: 10,
    fontFamily: "var(--font-mono)", fontWeight: 700, letterSpacing: "0.08em",
  },
  confirmedBadge: {
    padding: "2px 8px", borderRadius: 3, fontSize: 10,
    fontFamily: "var(--font-mono)", fontWeight: 700, letterSpacing: "0.08em",
    background: "rgba(16,185,129,0.15)", border: "1px solid var(--green)", color: "var(--green)",
  },
  directBadge: {
    padding: "2px 8px", borderRadius: 3, fontSize: 10,
    fontFamily: "var(--font-mono)", fontWeight: 700, letterSpacing: "0.08em",
    background: "rgba(0,212,255,0.1)", border: "1px solid var(--cyan)", color: "var(--cyan)",
  },
  cardRight: { display: "flex", alignItems: "center", gap: 10, flexShrink: 0 },
  sourceTag: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  confTag: { fontFamily: "var(--font-mono)", fontSize: 10 },
  expandArrow: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  hostsRow: {
    display: "flex", flexWrap: "wrap" as const, gap: 6,
    padding: "8px 14px", background: "var(--bg-panel)",
    borderTop: "1px solid var(--border)",
  },
  hostChip: {
    padding: "2px 8px", borderRadius: 3, fontSize: 10,
    fontFamily: "var(--font-mono)", color: "var(--text-secondary)",
    background: "var(--bg-hover)", border: "1px solid var(--border)",
  },
  moreChip: {
    padding: "2px 8px", borderRadius: 3, fontSize: 10,
    fontFamily: "var(--font-mono)", color: "var(--text-muted)",
  },
  expandedBody: {
    padding: "12px 14px", borderTop: "1px solid var(--border)",
    background: "var(--bg-surface)",
  },
  detailGrid: { display: "flex", flexDirection: "column" as const, gap: 6 },
  detailRow: { display: "flex", gap: 16 },
  detailKey: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", width: 100, flexShrink: 0 },
  detailVal: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" },
};
