import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

type RecordData = {
  a:     string[];
  aaaa:  string[];
  cname: string[];
  mx:    string[];
  ns:    string[];
  txt:   string[];
  statusCode: string;
};

type DNSStatus = {
  status: "not_started" | "running" | "done" | "timeout" | "error";
  totalQueried?:  number;
  resolvedCount?: number;
  totalRecords?:  number;
  error?: string;
  records: Record<string, RecordData>;
};

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  timeout:     "var(--orange)",
  error:       "var(--red)",
  not_started: "var(--text-muted)",
};

const RECORD_COLORS: Record<string, string> = {
  a:     "var(--cyan)",
  aaaa:  "var(--amber)",
  cname: "var(--green)",
  mx:    "var(--orange)",
  ns:    "#a78bfa",
  txt:   "var(--text-secondary)",
};

function RecordBadge({ type, values }: { type: string; values: string[] }) {
  if (!values || values.length === 0) return null;
  const color = RECORD_COLORS[type] || "var(--text-muted)";
  return (
    <div style={{ marginBottom: 6 }}>
      <span style={{
        display: "inline-block",
        padding: "1px 7px",
        borderRadius: 3,
        fontFamily: "var(--font-mono)",
        fontSize: 9,
        fontWeight: 700,
        letterSpacing: "0.1em",
        background: `${color}22`,
        border: `1px solid ${color}`,
        color,
        marginRight: 8,
        textTransform: "uppercase" as const,
      }}>
        {type}
      </span>
      {values.map((v, i) => (
        <span key={i} style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          color: "var(--text-secondary)",
          marginRight: 12,
        }}>
          {v}
        </span>
      ))}
    </div>
  );
}

export default function DNSPage() {
  const [targets, setTargets]     = useState<string[]>([]);
  const [selected, setSelected]   = useState("");
  const [dnsData, setDnsData]     = useState<DNSStatus | null>(null);
  const [loading, setLoading]     = useState(false);
  const [filter, setFilter]       = useState("");
  const [expandAll, setExpandAll] = useState(false);
  const [expanded, setExpanded]   = useState<Set<string>>(new Set());
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
    setDnsData(null);
    setFilter("");
    setExpanded(new Set());
    const res = await axios.get(`${API}/dns/${target}`);
    setDnsData(res.data);
    if (res.data.status === "running") startPolling(target);
  };

  const runDNS = async () => {
    if (!selected) return;
    setLoading(true);
    setDnsData(prev => prev ? { ...prev, status: "running" } : { status: "running", records: {} });
    await axios.post(`${API}/dns/${selected}`);
    startPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const res = await axios.get(`${API}/dns/${target}`);
      setDnsData(res.data);
      if (res.data.status !== "running") {
        stopPolling();
        setLoading(false);
      }
    }, 3000);
  };

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const toggleExpand = (host: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(host) ? next.delete(host) : next.add(host);
      return next;
    });
  };

  const isRunning = loading || dnsData?.status === "running";

  const allHosts = dnsData?.records ? Object.entries(dnsData.records) : [];
  const filteredHosts = filter
    ? allHosts.filter(([host]) => host.toLowerCase().includes(filter.toLowerCase()))
    : allHosts;

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 02</div>
          <h1 style={s.title}>DNS Resolution</h1>
        </div>
        {dnsData?.resolvedCount !== undefined && (
          <div style={s.countBox}>
            <span style={s.countNum}>{dnsData.resolvedCount}</span>
            <span style={s.countLabel}>resolved</span>
          </div>
        )}
      </div>

      <div style={s.layout}>
        {/* Target sidebar */}
        <div style={s.targetList}>
          <div style={s.listLabel}>TARGETS</div>
          {targets.map(t => (
            <button
              key={t}
              onClick={() => selectTarget(t)}
              style={{ ...s.targetBtn, ...(selected === t ? s.targetBtnActive : {}) }}
            >
              <span style={s.targetDot} />
              {t}
            </button>
          ))}
        </div>

        {/* Results */}
        <div style={s.results}>
          {!selected ? (
            <div style={s.empty}>
              <div style={s.emptyIcon}>◎</div>
              <div style={s.emptyText}>Select a target to run DNS resolution</div>
              <div style={s.emptyHint}>Requires Phase 01 (Subdomains) to be completed first</div>
            </div>
          ) : (
            <>
              {/* Toolbar */}
              <div style={s.toolbar}>
                <div style={s.searchBox}>
                  <span style={s.searchIcon}>⌕</span>
                  <input
                    value={filter}
                    onChange={e => setFilter(e.target.value)}
                    placeholder="Filter by hostname..."
                    style={s.searchInput}
                    spellCheck={false}
                  />
                  {filter && (
                    <button onClick={() => setFilter("")} style={s.clearBtn}>✕</button>
                  )}
                </div>

                {dnsData && (
                  <div style={{
                    ...s.badge,
                    background: `${STATUS_COLOR[dnsData.status]}22`,
                    border: `1px solid ${STATUS_COLOR[dnsData.status]}`,
                    color: STATUS_COLOR[dnsData.status],
                  }}>
                    <span
                      style={{ ...s.badgeDot, background: STATUS_COLOR[dnsData.status] }}
                      className={dnsData.status === "running" ? "pulse" : ""}
                    />
                    {dnsData.status}
                  </div>
                )}

                <button
                  onClick={runDNS}
                  disabled={isRunning}
                  style={{
                    ...s.runBtn,
                    opacity: isRunning ? 0.45 : 1,
                    cursor: isRunning ? "not-allowed" : "pointer",
                  }}
                >
                  {isRunning ? "RESOLVING..." : "RUN DNS"}
                </button>
              </div>

              {/* Stats */}
              {dnsData?.resolvedCount !== undefined && (
                <div style={s.statsRow}>
                  <div style={s.stat}>
                    <span style={s.statNum}>{dnsData.totalQueried}</span>
                    <span style={s.statLabel}>queried</span>
                  </div>
                  <div style={s.statDivider} />
                  <div style={s.stat}>
                    <span style={s.statNum}>{dnsData.resolvedCount}</span>
                    <span style={s.statLabel}>resolved</span>
                  </div>
                  <div style={s.statDivider} />
                  <div style={s.stat}>
                    <span style={{ ...s.statNum, color: "var(--red)" }}>
                      {(dnsData.totalQueried || 0) - (dnsData.resolvedCount || 0)}
                    </span>
                    <span style={s.statLabel}>unresolved</span>
                  </div>
                  <div style={s.statDivider} />
                  <div style={{ marginLeft: "auto" }}>
                    <button
                      onClick={() => {
                        if (expandAll) {
                          setExpanded(new Set());
                        } else {
                          setExpanded(new Set(filteredHosts.map(([h]) => h)));
                        }
                        setExpandAll(!expandAll);
                      }}
                      style={s.expandBtn}
                    >
                      {expandAll ? "COLLAPSE ALL" : "EXPAND ALL"}
                    </button>
                  </div>
                </div>
              )}

              {/* Error */}
              {dnsData?.status === "error" && dnsData.error && (
                <div style={s.errorBox}>
                  <span style={s.errorIcon}>✕</span>
                  {dnsData.error}
                </div>
              )}

              {/* Not started */}
              {(!dnsData || dnsData.status === "not_started") && !loading && (
                <div style={s.empty}>
                  <div style={s.emptyText}>Click "Run DNS" to resolve subdomains</div>
                  <div style={s.emptyHint}>Resolves A, CNAME, MX, NS, TXT records for all subdomains</div>
                </div>
              )}

              {/* Records list */}
              {filteredHosts.length > 0 && (
                <div style={s.hostList}>
                  {filteredHosts.map(([host, rec]) => {
                    const isExp = expanded.has(host);
                    const hasA  = rec.a?.length > 0;
                    const hasCname = rec.cname?.length > 0;
                    const resolved = hasA || hasCname;
                    return (
                      <div key={host} className="animate-in" style={s.hostCard}>
                        <div
                          style={{ ...s.hostHeader, cursor: "pointer" }}
                          onClick={() => toggleExpand(host)}
                        >
                          <div style={s.hostLeft}>
                            <span style={{
                              ...s.resolvedDot,
                              background: resolved ? "var(--green)" : "var(--red)",
                              boxShadow: resolved ? "0 0 5px var(--green)" : "none",
                            }} />
                            <span style={s.hostName}>{host}</span>
                          </div>
                          <div style={s.hostRight}>
                            {rec.a?.slice(0, 2).map((ip, i) => (
                              <span key={i} style={s.ipChip}>{ip}</span>
                            ))}
                            {rec.cname?.[0] && (
                              <span style={{ ...s.ipChip, color: "var(--green)", borderColor: "var(--green)" }}>
                                → {rec.cname[0]}
                              </span>
                            )}
                            <span style={s.expandArrow}>{isExp ? "▴" : "▾"}</span>
                          </div>
                        </div>

                        {isExp && (
                          <div style={s.recordBody}>
                            <RecordBadge type="a"     values={rec.a} />
                            <RecordBadge type="aaaa"  values={rec.aaaa} />
                            <RecordBadge type="cname" values={rec.cname} />
                            <RecordBadge type="mx"    values={rec.mx} />
                            <RecordBadge type="ns"    values={rec.ns} />
                            <RecordBadge type="txt"   values={rec.txt} />
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {dnsData?.status === "done" && filteredHosts.length === 0 && (
                <div style={s.empty}>
                  <div style={s.emptyText}>
                    {filter ? "No hosts match filter" : "No DNS records found"}
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
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 28,
  },
  phase: {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--cyan)",
    letterSpacing: "0.2em",
    marginBottom: 6,
  },
  title: { fontSize: 26, fontWeight: 600, letterSpacing: "-0.02em" },
  countBox: { display: "flex", flexDirection: "column", alignItems: "flex-end" },
  countNum: {
    fontFamily: "var(--font-mono)",
    fontSize: 34,
    fontWeight: 700,
    color: "var(--cyan)",
    lineHeight: 1,
  },
  countLabel: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  layout: { display: "flex", gap: 20, alignItems: "flex-start" },
  targetList: {
    width: 190,
    flexShrink: 0,
    display: "flex",
    flexDirection: "column",
    gap: 4,
  },
  listLabel: {
    fontFamily: "var(--font-mono)",
    fontSize: 9,
    color: "var(--text-muted)",
    letterSpacing: "0.2em",
    marginBottom: 8,
    paddingLeft: 4,
  },
  targetBtn: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "9px 11px",
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 5,
    color: "var(--text-secondary)",
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    cursor: "pointer",
    textAlign: "left" as const,
    width: "100%",
    wordBreak: "break-all" as const,
    transition: "all 0.15s",
  },
  targetBtnActive: {
    border: "1px solid var(--cyan)",
    color: "var(--cyan)",
    background: "var(--cyan-glow)",
  },
  targetDot: {
    display: "inline-block",
    width: 5,
    height: 5,
    borderRadius: "50%",
    background: "currentColor",
    flexShrink: 0,
  },
  results: { flex: 1, minWidth: 0 },
  toolbar: {
    display: "flex",
    gap: 10,
    alignItems: "center",
    marginBottom: 14,
    flexWrap: "wrap" as const,
  },
  searchBox: {
    flex: 1,
    minWidth: 180,
    display: "flex",
    alignItems: "center",
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 5,
    padding: "0 12px",
    gap: 8,
  },
  searchIcon: { color: "var(--text-muted)", fontSize: 16 },
  searchInput: {
    flex: 1,
    background: "transparent",
    border: "none",
    outline: "none",
    color: "var(--text-primary)",
    fontFamily: "var(--font-mono)",
    fontSize: 12,
    padding: "9px 0",
  },
  clearBtn: {
    background: "transparent",
    border: "none",
    color: "var(--text-muted)",
    cursor: "pointer",
    fontSize: 11,
    padding: 2,
  },
  badge: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    padding: "6px 12px",
    borderRadius: 4,
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    whiteSpace: "nowrap" as const,
  },
  badgeDot: { width: 6, height: 6, borderRadius: "50%", flexShrink: 0 },
  runBtn: {
    background: "var(--cyan)",
    color: "var(--bg-base)",
    border: "none",
    borderRadius: 5,
    padding: "9px 16px",
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: "0.08em",
    whiteSpace: "nowrap" as const,
    transition: "opacity 0.15s",
  },
  statsRow: {
    display: "flex",
    alignItems: "center",
    gap: 20,
    padding: "12px 16px",
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    marginBottom: 14,
  },
  stat: { display: "flex", alignItems: "baseline", gap: 8 },
  statNum: { fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 700, color: "var(--cyan)" },
  statLabel: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
  statDivider: { width: 1, height: 24, background: "var(--border)" },
  expandBtn: {
    background: "transparent",
    border: "1px solid var(--border)",
    borderRadius: 4,
    padding: "5px 10px",
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--text-muted)",
    cursor: "pointer",
    letterSpacing: "0.08em",
  },
  errorBox: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    padding: "12px 16px",
    background: "rgba(239,68,68,0.08)",
    border: "1px solid var(--red)",
    borderRadius: 6,
    color: "var(--red)",
    fontFamily: "var(--font-mono)",
    fontSize: 12,
    marginBottom: 14,
  },
  errorIcon: { fontWeight: 700 },
  empty: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    padding: "64px 0",
    gap: 8,
  },
  emptyIcon: { fontSize: 30, color: "var(--border-bright)", marginBottom: 8 },
  emptyText: { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-muted)" },
  emptyHint: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", opacity: 0.6 },
  hostList: { display: "flex", flexDirection: "column", gap: 6 },
  hostCard: {
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    overflow: "hidden",
  },
  hostHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "10px 14px",
    gap: 12,
  },
  hostLeft: { display: "flex", alignItems: "center", gap: 10, minWidth: 0 },
  resolvedDot: {
    width: 7,
    height: 7,
    borderRadius: "50%",
    flexShrink: 0,
  },
  hostName: {
    fontFamily: "var(--font-mono)",
    fontSize: 12,
    color: "var(--text-primary)",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap" as const,
  },
  hostRight: {
    display: "flex",
    alignItems: "center",
    gap: 6,
    flexShrink: 0,
  },
  ipChip: {
    padding: "2px 8px",
    background: "var(--bg-hover)",
    border: "1px solid var(--border-bright)",
    borderRadius: 3,
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--cyan)",
    whiteSpace: "nowrap" as const,
  },
  expandArrow: {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--text-muted)",
    marginLeft: 4,
  },
  recordBody: {
    padding: "12px 14px",
    borderTop: "1px solid var(--border)",
    background: "var(--bg-surface)",
  },
};
