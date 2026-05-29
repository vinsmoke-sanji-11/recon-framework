import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

type NmapPort = {
  port:    number;
  service: string;
  product: string;
  version: string;
};

type HostData = {
  naabu: number[];
  nmap:  NmapPort[];
};

type PortsStatus = {
  status: "not_started" | "running" | "done" | "timeout" | "error";
  step?:          string;
  totalOpenPorts?: number;
  totalHosts?:     number;
  naabuPortCount?: number;
  naabuHostCount?: number;
  nmapHostCount?:  number;
  nmapSkipped?:    boolean;
  error?: string;
  merged: Record<string, HostData>;
};

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  timeout:     "var(--orange)",
  error:       "var(--red)",
  not_started: "var(--text-muted)",
};

const INTERESTING_PORTS = new Set([
  21, 22, 23, 25, 53, 110, 143, 389, 445, 512, 513, 514,
  1433, 1521, 2181, 2375, 2376, 3000, 3306, 3389, 4848,
  5432, 5900, 6379, 7001, 8080, 8443, 8888, 9200, 9300,
  27017, 28017,
]);

const PORT_LABELS: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
  80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
  445: "smb", 1433: "mssql", 1521: "oracle", 2375: "docker",
  3000: "dev", 3306: "mysql", 3389: "rdp", 5432: "postgres",
  5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
  9200: "elasticsearch", 27017: "mongodb",
};

function PortBadge({ port, nmapData }: { port: number; nmapData?: NmapPort }) {
  const label     = nmapData?.service || PORT_LABELS[port] || '';
  const version   = nmapData?.version ? `${nmapData.product || ''} ${nmapData.version}`.trim() : '';
  const risky     = INTERESTING_PORTS.has(port);
  const color     = risky ? "var(--red)" : "var(--text-secondary)";
  const bg        = risky ? "rgba(239,68,68,0.08)" : "var(--bg-hover)";
  const border    = risky ? "var(--red)" : "var(--border-bright)";

  return (
    <div style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 6,
      padding: "3px 9px",
      borderRadius: 3,
      background: bg,
      border: `1px solid ${border}`,
      marginRight: 6,
      marginBottom: 6,
    }}>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color, fontWeight: 600 }}>
        {port}
      </span>
      {label && (
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: risky ? "var(--red)" : "var(--text-muted)" }}>
          {label}
        </span>
      )}
      {version && (
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
          {version}
        </span>
      )}
    </div>
  );
}

export default function PortsPage() {
  const [targets, setTargets]     = useState<string[]>([]);
  const [selected, setSelected]   = useState("");
  const [portsData, setPortsData] = useState<PortsStatus | null>(null);
  const [loading, setLoading]     = useState(false);
  const [filter, setFilter]       = useState("");
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
    setPortsData(null);
    setFilter("");
    setExpanded(new Set());
    const res = await axios.get(`${API}/ports/${target}`);
    setPortsData(res.data);
    if (res.data.status === "running") startPolling(target);
  };

  const runScan = async () => {
    if (!selected) return;
    setLoading(true);
    setPortsData(prev => prev
      ? { ...prev, status: "running", step: "naabu" }
      : { status: "running", step: "naabu", merged: {} }
    );
    await axios.post(`${API}/ports/${selected}`);
    startPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const res = await axios.get(`${API}/ports/${target}`);
      setPortsData(res.data);
      if (res.data.status !== "running") {
        stopPolling();
        setLoading(false);
      }
    }, 4000);
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

  const isRunning = loading || portsData?.status === "running";

  const allHosts = portsData?.merged ? Object.entries(portsData.merged) : [];
  const filteredHosts = filter
    ? allHosts.filter(([host]) => host.toLowerCase().includes(filter.toLowerCase()))
    : allHosts;

  // Step label
  const stepLabel = portsData?.step === "naabu"
    ? "Running naabu (fast discovery)..."
    : portsData?.step === "nmap"
    ? `Running nmap (deep scan)... naabu found ${portsData.naabuPortCount} ports`
    : "";

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 04</div>
          <h1 style={s.title}>Port Scan</h1>
        </div>
        {portsData?.totalOpenPorts !== undefined && (
          <div style={s.countBox}>
            <span style={s.countNum}>{portsData.totalOpenPorts}</span>
            <span style={s.countLabel}>open ports</span>
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
              <div style={s.emptyIcon}>⬡</div>
              <div style={s.emptyText}>Select a target to run port scan</div>
              <div style={s.emptyHint}>Requires Phase 03 (Live Hosts) to be completed first</div>
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
                  {filter && <button onClick={() => setFilter("")} style={s.clearBtn}>✕</button>}
                </div>

                {portsData && (
                  <div style={{
                    ...s.badge,
                    background: `${STATUS_COLOR[portsData.status]}22`,
                    border: `1px solid ${STATUS_COLOR[portsData.status]}`,
                    color: STATUS_COLOR[portsData.status],
                  }}>
                    <span
                      style={{ ...s.badgeDot, background: STATUS_COLOR[portsData.status] }}
                      className={isRunning ? "pulse" : ""}
                    />
                    {portsData.status}
                  </div>
                )}

                <button
                  onClick={runScan}
                  disabled={isRunning}
                  style={{
                    ...s.runBtn,
                    opacity: isRunning ? 0.45 : 1,
                    cursor: isRunning ? "not-allowed" : "pointer",
                  }}
                >
                  {isRunning ? "SCANNING..." : "RUN SCAN"}
                </button>
              </div>

              {/* Step indicator */}
              {isRunning && stepLabel && (
                <div style={s.stepBox} className="pulse">
                  <span style={s.stepDot} />
                  {stepLabel}
                </div>
              )}

              {/* Stats */}
              {portsData?.totalOpenPorts !== undefined && (
                <div style={s.statsRow}>
                  <div style={s.stat}>
                    <span style={s.statNum}>{portsData.totalOpenPorts}</span>
                    <span style={s.statLabel}>open ports</span>
                  </div>
                  <div style={s.statDivider} />
                  <div style={s.stat}>
                    <span style={s.statNum}>{portsData.totalHosts}</span>
                    <span style={s.statLabel}>hosts</span>
                  </div>
                  <div style={s.statDivider} />
                  <div style={s.stat}>
                    <span style={{ ...s.statNum, fontSize: 14, color: "var(--green)" }}>naabu</span>
                    <span style={s.statLabel}>{portsData.naabuPortCount} ports</span>
                  </div>
                  <div style={s.statDivider} />
                  <div style={s.stat}>
                    <span style={{ ...s.statNum, fontSize: 14, color: "var(--amber)" }}>nmap</span>
                    <span style={s.statLabel}>
                      {portsData.nmapSkipped ? "skipped" : `${portsData.nmapHostCount} hosts`}
                    </span>
                  </div>
                </div>
              )}

              {/* Error */}
              {portsData?.status === "error" && portsData.error && (
                <div style={s.errorBox}>
                  <span>✕</span> {portsData.error}
                </div>
              )}

              {/* Not started */}
              {(!portsData || portsData.status === "not_started") && !loading && (
                <div style={s.empty}>
                  <div style={s.emptyText}>Click "Run Scan" to start port scanning</div>
                  <div style={s.emptyHint}>naabu discovers open ports fast, nmap adds service details</div>
                </div>
              )}

              {/* Host cards */}
              {filteredHosts.length > 0 && (
                <div style={s.hostList}>
                  {filteredHosts.map(([host, data]) => {
                    const isExp     = expanded.has(host);
                    const portCount = data.naabu.length;
                    const hasNmap   = data.nmap.length > 0;
                    const nmapMap   = Object.fromEntries(data.nmap.map(n => [n.port, n]));

                    return (
                      <div key={host} className="animate-in" style={s.hostCard}>
                        <div
                          style={{ ...s.hostHeader, cursor: "pointer" }}
                          onClick={() => toggleExpand(host)}
                        >
                          <div style={s.hostLeft}>
                            <span style={s.hostName}>{host}</span>
                            {hasNmap && (
                              <span style={s.nmapTag}>nmap ✓</span>
                            )}
                          </div>
                          <div style={s.hostRight}>
                            <span style={s.portCountBadge}>{portCount} port{portCount !== 1 ? "s" : ""}</span>
                            <span style={s.expandArrow}>{isExp ? "▴" : "▾"}</span>
                          </div>
                        </div>

                        {/* Collapsed preview — show first 6 ports */}
                        {!isExp && (
                          <div style={{ padding: "8px 14px 10px", display: "flex", flexWrap: "wrap" as const }}>
                            {data.naabu.slice(0, 6).map(port => (
                              <PortBadge key={port} port={port} nmapData={nmapMap[port]} />
                            ))}
                            {data.naabu.length > 6 && (
                              <span style={s.moreTag}>+{data.naabu.length - 6} more</span>
                            )}
                          </div>
                        )}

                        {/* Expanded — all ports with nmap details */}
                        {isExp && (
                          <div style={s.expandedBody}>
                            <div style={{ display: "flex", flexWrap: "wrap" as const }}>
                              {data.naabu.map(port => (
                                <PortBadge key={port} port={port} nmapData={nmapMap[port]} />
                              ))}
                            </div>

                            {data.nmap.length > 0 && (
                              <>
                                <div style={s.nmapDivider}>NMAP SERVICE DETAILS</div>
                                <table style={s.nmapTable}>
                                  <thead>
                                    <tr>
                                      <th style={s.nmapTh}>PORT</th>
                                      <th style={s.nmapTh}>SERVICE</th>
                                      <th style={s.nmapTh}>PRODUCT</th>
                                      <th style={s.nmapTh}>VERSION</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {data.nmap.map((n, i) => (
                                      <tr key={i}>
                                        <td style={s.nmapTd}>
                                          <span style={{ color: INTERESTING_PORTS.has(n.port) ? "var(--red)" : "var(--cyan)" }}>
                                            {n.port}
                                          </span>
                                        </td>
                                        <td style={s.nmapTd}>{n.service || "—"}</td>
                                        <td style={s.nmapTd}>{n.product || "—"}</td>
                                        <td style={s.nmapTd}>{n.version || "—"}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {portsData?.status === "done" && filteredHosts.length === 0 && (
                <div style={s.empty}>
                  <div style={s.emptyText}>
                    {filter ? "No hosts match filter" : "No open ports found"}
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
  targetList: { width: 190, flexShrink: 0, display: "flex", flexDirection: "column", gap: 4 },
  listLabel: { fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.2em", marginBottom: 8, paddingLeft: 4 },
  targetBtn: {
    display: "flex", alignItems: "center", gap: 8, padding: "9px 11px",
    background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 5,
    color: "var(--text-secondary)", fontFamily: "var(--font-mono)", fontSize: 11,
    cursor: "pointer", textAlign: "left" as const, width: "100%",
    wordBreak: "break-all" as const, transition: "all 0.15s",
  },
  targetBtnActive: { border: "1px solid var(--cyan)", color: "var(--cyan)", background: "var(--cyan-glow)" },
  targetDot: { display: "inline-block", width: 5, height: 5, borderRadius: "50%", background: "currentColor", flexShrink: 0 },
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
  stepBox: {
    display: "flex", alignItems: "center", gap: 10,
    padding: "10px 14px", marginBottom: 14,
    background: "rgba(0,212,255,0.06)", border: "1px solid var(--cyan)",
    borderRadius: 6, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--cyan)",
  },
  stepDot: { width: 7, height: 7, borderRadius: "50%", background: "var(--cyan)", flexShrink: 0 },
  statsRow: {
    display: "flex", alignItems: "center", gap: 20, padding: "12px 16px",
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, marginBottom: 14, flexWrap: "wrap" as const,
  },
  stat: { display: "flex", alignItems: "baseline", gap: 8 },
  statNum: { fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 700, color: "var(--cyan)" },
  statLabel: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
  statDivider: { width: 1, height: 24, background: "var(--border)" },
  errorBox: {
    display: "flex", alignItems: "center", gap: 10, padding: "12px 16px",
    background: "rgba(239,68,68,0.08)", border: "1px solid var(--red)",
    borderRadius: 6, color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 14,
  },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", padding: "64px 0", gap: 8 },
  emptyIcon: { fontSize: 30, color: "var(--border-bright)", marginBottom: 8 },
  emptyText: { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-muted)" },
  emptyHint: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", opacity: 0.6 },
  hostList: { display: "flex", flexDirection: "column", gap: 8 },
  hostCard: { background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" },
  hostHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "var(--bg-surface)" },
  hostLeft: { display: "flex", alignItems: "center", gap: 10 },
  hostName: { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--cyan)" },
  nmapTag: {
    padding: "1px 7px", borderRadius: 3, fontSize: 9,
    fontFamily: "var(--font-mono)", letterSpacing: "0.08em",
    background: "rgba(245,158,11,0.1)", border: "1px solid var(--amber)", color: "var(--amber)",
  },
  hostRight: { display: "flex", alignItems: "center", gap: 8 },
  portCountBadge: {
    padding: "2px 8px", background: "var(--bg-hover)", border: "1px solid var(--border-bright)",
    borderRadius: 3, fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)",
  },
  expandArrow: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  moreTag: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", padding: "3px 8px", alignSelf: "center" },
  expandedBody: { padding: "12px 14px", borderTop: "1px solid var(--border)" },
  nmapDivider: {
    fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)",
    letterSpacing: "0.15em", marginTop: 14, marginBottom: 10,
    borderTop: "1px solid var(--border)", paddingTop: 10,
  },
  nmapTable: { width: "100%", borderCollapse: "collapse" },
  nmapTh: {
    padding: "6px 10px", background: "var(--bg-surface)",
    fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)",
    letterSpacing: "0.12em", textAlign: "left" as const, borderBottom: "1px solid var(--border)",
  },
  nmapTd: {
    padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 11,
    color: "var(--text-secondary)", borderBottom: "1px solid var(--border)",
  },
};
