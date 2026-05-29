import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

type Host = {
  url: string;
  hostname: string;
  statusCode: number | null;
  title: string;
  webServer: string;
  ip: string;
  techStack: string[];
};

type LiveStatus = {
  status: "not_started" | "running" | "done" | "timeout" | "error";
  liveCount?: number;
  hostCount?: number;
  error?: string;
  hosts: Host[];
};

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  timeout:     "var(--orange)",
  error:       "var(--red)",
  not_started: "var(--text-muted)",
};

function codeColor(code: number | null): string {
  if (!code) return "var(--text-muted)";
  if (code >= 200 && code < 300) return "var(--green)";
  if (code >= 300 && code < 400) return "var(--amber)";
  return "var(--red)";
}

export default function LivePage() {
  const [targets, setTargets]       = useState<string[]>([]);
  const [selected, setSelected]     = useState("");
  const [liveData, setLiveData]     = useState<LiveStatus | null>(null);
  const [loading, setLoading]       = useState(false);
  const [filter, setFilter]         = useState("");
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
    setLiveData(null);
    setFilter("");
    const res = await axios.get(`${API}/live/${target}`);
    setLiveData(res.data);
    if (res.data.status === "running") startPolling(target);
  };

  const runLive = async () => {
    if (!selected) return;
    setLoading(true);
    setLiveData(prev => prev ? { ...prev, status: "running" } : { status: "running", hosts: [] });
    await axios.post(`${API}/live/${selected}`);
    startPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const res = await axios.get(`${API}/live/${target}`);
      setLiveData(res.data);
      if (res.data.status !== "running") {
        stopPolling();
        setLoading(false);
      }
    }, 3000);
  };

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const isRunning = loading || liveData?.status === "running";

  const filtered = filter && liveData?.hosts
    ? liveData.hosts.filter(h =>
        h.url.toLowerCase().includes(filter.toLowerCase()) ||
        h.title.toLowerCase().includes(filter.toLowerCase()) ||
        h.webServer.toLowerCase().includes(filter.toLowerCase())
      )
    : liveData?.hosts || [];

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 02</div>
          <h1 style={s.title}>Live Hosts</h1>
        </div>
        {liveData && liveData.liveCount !== undefined && (
          <div style={s.countBox}>
            <span style={s.countNum}>{filtered.length}</span>
            <span style={s.countLabel}>{filter ? `of ${liveData.liveCount}` : "live"}</span>
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
              <div style={s.emptyIcon}>◉</div>
              <div style={s.emptyText}>Select a target to detect live hosts</div>
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
                    placeholder="Filter by URL, title, server..."
                    style={s.searchInput}
                    spellCheck={false}
                  />
                  {filter && (
                    <button onClick={() => setFilter("")} style={s.clearBtn}>✕</button>
                  )}
                </div>

                {/* Status badge */}
                {liveData && (
                  <div style={{
                    ...s.badge,
                    background: `${STATUS_COLOR[liveData.status]}22`,
                    border: `1px solid ${STATUS_COLOR[liveData.status]}`,
                    color: STATUS_COLOR[liveData.status],
                  }}>
                    <span
                      style={{ ...s.badgeDot, background: STATUS_COLOR[liveData.status] }}
                      className={liveData.status === "running" ? "pulse" : ""}
                    />
                    {liveData.status}
                  </div>
                )}

                {/* Run button */}
                <button
                  onClick={runLive}
                  disabled={isRunning}
                  style={{
                    ...s.runBtn,
                    opacity: isRunning ? 0.45 : 1,
                    cursor: isRunning ? "not-allowed" : "pointer",
                  }}
                >
                  {isRunning ? "SCANNING..." : "RUN DETECTION"}
                </button>
              </div>

              {/* Stats row */}
              {liveData && liveData.liveCount !== undefined && (
                <div style={s.statsRow}>
                  <div style={s.stat}>
                    <span style={s.statNum}>{liveData.liveCount}</span>
                    <span style={s.statLabel}>live URLs</span>
                  </div>
                  <div style={s.statDivider} />
                  <div style={s.stat}>
                    <span style={s.statNum}>{liveData.hostCount}</span>
                    <span style={s.statLabel}>unique hosts</span>
                  </div>
                </div>
              )}

              {/* Error */}
              {liveData?.status === "error" && liveData.error && (
                <div style={s.errorBox}>
                  <span style={s.errorIcon}>✕</span>
                  {liveData.error}
                </div>
              )}

              {/* Not started */}
              {(!liveData || liveData.status === "not_started") && !loading && (
                <div style={s.empty}>
                  <div style={s.emptyText}>Click "Run Detection" to probe live hosts</div>
                </div>
              )}

              {/* Table */}
              {filtered.length > 0 && (
                <div style={s.tableWrap}>
                  <table style={s.table}>
                    <thead>
                      <tr>
                        <th style={s.th}>#</th>
                        <th style={s.th}>URL</th>
                        <th style={{ ...s.th, width: 60 }}>CODE</th>
                        <th style={s.th}>TITLE</th>
                        <th style={s.th}>SERVER</th>
                        <th style={s.th}>IP</th>
                        <th style={s.th}>TECH</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((host, i) => (
                        <tr key={i} className="animate-in">
                          <td style={s.tdIdx}>{String(i + 1).padStart(3, "0")}</td>
                          <td style={s.tdUrl}>
                            <a href={host.url} target="_blank" rel="noreferrer" style={s.link}>
                              {host.url}
                            </a>
                          </td>
                          <td style={{ ...s.tdCode, color: codeColor(host.statusCode) }}>
                            {host.statusCode ?? "—"}
                          </td>
                          <td style={s.tdNorm}>{host.title || "—"}</td>
                          <td style={s.tdMono}>{host.webServer || "—"}</td>
                          <td style={s.tdMono}>{host.ip || "—"}</td>
                          <td style={s.tdTech}>
                            {host.techStack?.length
                              ? host.techStack.slice(0, 3).map((t, ti) => (
                                  <span key={ti} style={s.techTag}>{t}</span>
                                ))
                              : <span style={{ color: "var(--text-muted)" }}>—</span>
                            }
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
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
  title: {
    fontSize: 26,
    fontWeight: 600,
    letterSpacing: "-0.02em",
  },
  countBox: { display: "flex", flexDirection: "column", alignItems: "flex-end" },
  countNum: {
    fontFamily: "var(--font-mono)",
    fontSize: 34,
    fontWeight: 700,
    color: "var(--cyan)",
    lineHeight: 1,
  },
  countLabel: {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--text-muted)",
  },
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
  badgeDot: {
    width: 6,
    height: 6,
    borderRadius: "50%",
    flexShrink: 0,
  },
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
  statNum: {
    fontFamily: "var(--font-mono)",
    fontSize: 22,
    fontWeight: 700,
    color: "var(--cyan)",
  },
  statLabel: {
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    color: "var(--text-muted)",
  },
  statDivider: {
    width: 1,
    height: 24,
    background: "var(--border)",
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
  tableWrap: {
    border: "1px solid var(--border)",
    borderRadius: 6,
    overflow: "hidden",
    overflowX: "auto" as const,
  },
  table: { width: "100%", borderCollapse: "collapse", minWidth: 900 },
  th: {
    padding: "10px 12px",
    background: "var(--bg-surface)",
    borderBottom: "1px solid var(--border)",
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    fontWeight: 600,
    color: "var(--text-muted)",
    letterSpacing: "0.12em",
    textAlign: "left" as const,
    whiteSpace: "nowrap" as const,
  },
  tdIdx: {
    padding: "9px 12px",
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    color: "var(--text-muted)",
    borderBottom: "1px solid var(--border)",
    background: "var(--bg-panel)",
    width: 52,
  },
  tdUrl: {
    padding: "9px 12px",
    borderBottom: "1px solid var(--border)",
    maxWidth: 280,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap" as const,
  },
  link: {
    fontFamily: "var(--font-mono)",
    fontSize: 12,
    color: "var(--cyan)",
    textDecoration: "none",
  },
  tdCode: {
    padding: "9px 12px",
    fontFamily: "var(--font-mono)",
    fontSize: 12,
    fontWeight: 700,
    borderBottom: "1px solid var(--border)",
    textAlign: "center" as const,
  },
  tdNorm: {
    padding: "9px 12px",
    fontSize: 12,
    color: "var(--text-secondary)",
    borderBottom: "1px solid var(--border)",
    maxWidth: 180,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap" as const,
  },
  tdMono: {
    padding: "9px 12px",
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    color: "var(--text-secondary)",
    borderBottom: "1px solid var(--border)",
    whiteSpace: "nowrap" as const,
  },
  tdTech: {
    padding: "9px 12px",
    borderBottom: "1px solid var(--border)",
  },
  techTag: {
    display: "inline-block",
    padding: "2px 7px",
    background: "var(--bg-hover)",
    border: "1px solid var(--border-bright)",
    borderRadius: 3,
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--text-secondary)",
    marginRight: 4,
    whiteSpace: "nowrap" as const,
  },
};
