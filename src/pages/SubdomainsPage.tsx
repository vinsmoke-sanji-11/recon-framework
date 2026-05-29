import { useEffect, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

const TOOL_LABELS: Record<string, string> = {
  subfinder:      "Subfinder",
  amass_passive:  "Amass Passive",
  amass_active:   "Amass Active",
  assetfinder:    "Assetfinder",
  sublist3r:      "Sublist3r",
  crtsh:          "CRT.sh",
  shuffledns:     "ShuffleDNS",
  metabigor:      "Metabigor",
  cloudenum:      "CloudEnum",
  subdomainizer:  "Subdomainizer",
};

const TOOL_ORDER = [
  "subfinder", "amass_passive", "amass_active",
  "assetfinder", "sublist3r", "crtsh",
  "shuffledns", "metabigor", "cloudenum", "subdomainizer",
];

type ScanStatus = {
  status: "not_started" | "running" | "completed" | "failed";
  subdomainCount?: number;
  tools?: Record<string, string>;
  completedAt?: string;
};

function toolColor(val: string): string {
  if (!val) return "var(--text-muted)";
  if (val === "running")  return "var(--cyan)";
  if (val === "done")     return "var(--green)";
  if (val === "timeout")  return "var(--orange)";
  if (val.startsWith("skipped")) return "var(--text-muted)";
  if (val === "error")    return "var(--red)";
  return "var(--text-muted)";
}

function toolIcon(val: string): string {
  if (!val) return "○";
  if (val === "running")  return "◌";
  if (val === "done")     return "●";
  if (val === "timeout")  return "◎";
  if (val.startsWith("skipped")) return "◌";
  return "○";
}

export default function SubdomainsPage() {
  const [targets, setTargets]         = useState<string[]>([]);
  const [selectedTarget, setSelected] = useState("");
  const [data, setData]               = useState<any[]>([]);
  const [scanStatus, setScanStatus]   = useState<ScanStatus | null>(null);
  const [filter, setFilter]           = useState("");
  const [pollTimer, setPollTimer]     = useState<ReturnType<typeof setInterval> | null>(null);
  const [oosText, setOosText]         = useState("");
  const [oosApplied, setOosApplied]   = useState(false);
  const [oosStats, setOosStats]       = useState<{ total: number; removed: number } | null>(null);
  const [oosLoading, setOosLoading]   = useState(false);

  useEffect(() => {
    loadTargets();
    return () => { if (pollTimer) clearInterval(pollTimer); };
  }, []);

  const loadTargets = async () => {
    const res = await axios.get(`${API}/targets`);
    setTargets(res.data || []);
  };

  const selectTarget = async (target: string) => {
    if (pollTimer) clearInterval(pollTimer);
    setSelected(target);
    setFilter("");
    setData([]);
    setScanStatus(null);
    setOosApplied(false);
    setOosStats(null);

    // Load subdomain status
    const statusRes = await axios.get(`${API}/status/${target}`);
    setScanStatus(statusRes.data);

    // Load subdomains if completed
    if (statusRes.data.status === "completed") {
      const subRes = await axios.get(`${API}/subdomains/${target}`);
      setData(subRes.data || []);
    }
    // Load saved OOS
    try {
      const oosRes = await axios.get(`${API}/subdomains/${target}/oos`);
      if (oosRes.data.oos?.length > 0) {
        setOosText(oosRes.data.oos.join("\n"));
        setOosApplied(true);
      }
    } catch {}

    // If running, poll status
    if (statusRes.data.status === "running") {
      startPolling(target);
    }
  };

  const startPolling = (target: string) => {
    const timer = setInterval(async () => {
      const statusRes = await axios.get(`${API}/status/${target}`);
      setScanStatus(statusRes.data);

      if (statusRes.data.status !== "running") {
        clearInterval(timer);
        setPollTimer(null);
        if (statusRes.data.status === "completed") {
          const subRes = await axios.get(`${API}/subdomains/${target}`);
          setData(subRes.data || []);
        }
      }
    }, 3000);
    setPollTimer(timer);
  };

  const applyOOS = async () => {
    if (!selectedTarget || !oosText.trim()) return;
    setOosLoading(true);
    const oosList = oosText.split("\n").map(s => s.trim()).filter(Boolean);
    try {
      const res = await axios.post(`${API}/subdomains/${selectedTarget}/oos`, { oos: oosList });
      setData(res.data.rows || []);
      setOosApplied(true);
      setOosStats({ total: res.data.total, removed: res.data.removed });
    } finally {
      setOosLoading(false);
    }
  };

  const clearOOS = async () => {
    if (!selectedTarget) return;
    setOosText("");
    setOosApplied(false);
    setOosStats(null);
    await axios.post(`${API}/subdomains/${selectedTarget}/oos`, { oos: [] });
    const subRes = await axios.get(`${API}/subdomains/${selectedTarget}`);
    setData(subRes.data || []);
  };

  const filtered = filter
    ? data.filter(r => r.subdomain.toLowerCase().includes(filter.toLowerCase()))
    : data;

  const isRunning = scanStatus?.status === "running";

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 01</div>
          <h1 style={s.title}>Subdomains</h1>
        </div>
        {scanStatus?.subdomainCount !== undefined && (
          <div style={s.countBox}>
            <span style={s.countNum}>{filtered.length}</span>
            <span style={s.countLabel}>{filter ? `of ${data.length}` : "found"}</span>
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
              style={{ ...s.targetBtn, ...(selectedTarget === t ? s.targetBtnActive : {}) }}
            >
              <span style={s.targetDot} />
              {t}
            </button>
          ))}
        </div>

        {/* Main content */}
        <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 14 }}>
          {!selectedTarget ? (
            <div style={s.empty}>
              <div style={s.emptyIcon}>◎</div>
              <div style={s.emptyText}>Select a target to view subdomains</div>
              <div style={s.emptyHint}>Run a scan from the Targets page first</div>
            </div>
          ) : (
            <>
              {/* Tool status panel — show while running or after complete */}
              {scanStatus && scanStatus.tools && (
                <div style={s.toolPanel}>
                  <div style={s.toolPanelHeader}>
                    <span style={s.toolPanelTitle}>ENUMERATION TOOLS</span>
                    {isRunning && (
                      <span style={s.runningBadge} className="pulse">RUNNING</span>
                    )}
                    {scanStatus.status === "completed" && (
                      <span style={s.doneBadge}>COMPLETE</span>
                    )}
                  </div>
                  <div style={s.toolGrid}>
                    {TOOL_ORDER.map(key => {
                      const val = scanStatus.tools?.[key] || "";
                      const color = toolColor(val);
                      const icon  = toolIcon(val);
                      const label = val.startsWith("skipped") ? "skipped" : val || "waiting";
                      return (
                        <div key={key} style={s.toolRow}>
                          <span style={{ ...s.toolIcon, color }}
                            className={val === "running" ? "pulse" : ""}
                          >
                            {icon}
                          </span>
                          <span style={s.toolName}>{TOOL_LABELS[key] || key}</span>
                          <span style={{ ...s.toolStatus, color }}>{label}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* OOS Filter Panel */}
              {selectedTarget && scanStatus?.status === "completed" && (
                <div style={s.oosPanel}>
                  <div style={s.oosPanelHeader}>
                    <span style={s.oosPanelTitle}>OUT-OF-SCOPE FILTER</span>
                    {oosApplied && oosStats && (
                      <span style={s.oosStatsBadge}>
                        <span style={{ color: "var(--red)" }}>−{oosStats.removed}</span>
                        <span style={{ color: "var(--text-muted)" }}> removed · </span>
                        <span style={{ color: "var(--green)" }}>{oosStats.total - oosStats.removed}</span>
                        <span style={{ color: "var(--text-muted)" }}> kept</span>
                      </span>
                    )}
                    {oosApplied && (
                      <button onClick={clearOOS} style={s.oosClearBtn}>CLEAR</button>
                    )}
                  </div>
                  <textarea
                    value={oosText}
                    onChange={e => { setOosText(e.target.value); setOosApplied(false); }}
                    placeholder={"help.automox.com\ncommunity.automox.com\n*.staging.example.com"}
                    style={s.oosTextarea}
                    spellCheck={false}
                  />
                  <div style={s.oosFooter}>
                    <span style={s.oosHint}>One domain per line · Wildcards supported (*.example.com)</span>
                    <button
                      onClick={applyOOS}
                      disabled={oosLoading || !oosText.trim()}
                      style={{
                        ...s.oosApplyBtn,
                        opacity: (oosLoading || !oosText.trim()) ? 0.45 : 1,
                        cursor: (oosLoading || !oosText.trim()) ? "not-allowed" : "pointer",
                      }}
                    >
                      {oosLoading ? "APPLYING..." : oosApplied ? "✓ APPLIED" : "APPLY FILTER"}
                    </button>
                  </div>
                </div>
              )}

              {/* Results toolbar */}
              {data.length > 0 && (
                <div style={s.toolbar}>
                  <div style={s.searchBox}>
                    <span style={s.searchIcon}>⌕</span>
                    <input
                      value={filter}
                      onChange={e => setFilter(e.target.value)}
                      placeholder="Filter subdomains..."
                      style={s.searchInput}
                      spellCheck={false}
                    />
                    {filter && (
                      <button onClick={() => setFilter("")} style={s.clearBtn}>✕</button>
                    )}
                  </div>
                  <div style={s.targetTag}>{selectedTarget}</div>
                </div>
              )}

              {/* Table */}
              {filtered.length > 0 ? (
                <div style={s.tableWrap}>
                  <table style={s.table}>
                    <thead>
                      <tr>
                        <th style={s.th}>#</th>
                        <th style={s.th}>SUBDOMAIN</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((row) => (
                        <tr key={row.id} className="animate-in">
                          <td style={s.tdIdx}>{String(row.id).padStart(3, "0")}</td>
                          <td style={s.tdMono}>{row.subdomain}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                !isRunning && scanStatus?.status !== "running" && selectedTarget && (
                  <div style={s.empty}>
                    <div style={s.emptyText}>
                      {data.length === 0
                        ? "No subdomains found yet"
                        : "No matches for filter"}
                    </div>
                  </div>
                )
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
  toolPanel: {
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    overflow: "hidden",
  },
  toolPanelHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "10px 14px",
    borderBottom: "1px solid var(--border)",
    background: "var(--bg-surface)",
  },
  toolPanelTitle: {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--text-muted)",
    letterSpacing: "0.15em",
  },
  runningBadge: {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--cyan)",
    letterSpacing: "0.1em",
  },
  doneBadge: {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--green)",
    letterSpacing: "0.1em",
  },
  toolGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    padding: "8px 0",
  },
  toolRow: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "7px 14px",
  },
  toolIcon: {
    fontSize: 12,
    width: 14,
    textAlign: "center" as const,
    flexShrink: 0,
  },
  toolName: {
    flex: 1,
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    color: "var(--text-secondary)",
  },
  toolStatus: {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    letterSpacing: "0.04em",
  },
  toolbar: {
    display: "flex",
    gap: 10,
    alignItems: "center",
  },
  searchBox: {
    flex: 1,
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
  targetTag: {
    padding: "6px 12px",
    background: "var(--cyan-glow)",
    border: "1px solid var(--cyan)",
    borderRadius: 4,
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    color: "var(--cyan)",
    whiteSpace: "nowrap" as const,
  },
  tableWrap: {
    border: "1px solid var(--border)",
    borderRadius: 6,
    overflow: "hidden",
  },
  table: {
    width: "100%",
    borderCollapse: "collapse",
  },
  th: {
    padding: "10px 14px",
    background: "var(--bg-surface)",
    borderBottom: "1px solid var(--border)",
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    fontWeight: 600,
    color: "var(--text-muted)",
    letterSpacing: "0.12em",
    textAlign: "left" as const,
  },
  tdIdx: {
    padding: "9px 14px",
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    color: "var(--text-muted)",
    borderBottom: "1px solid var(--border)",
    width: 60,
    background: "var(--bg-panel)",
  },
  tdMono: {
    padding: "9px 14px",
    fontFamily: "var(--font-mono)",
    fontSize: 12,
    color: "var(--text-primary)",
    borderBottom: "1px solid var(--border)",
  },
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
  oosPanel: {
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    overflow: "hidden",
  },
  oosPanelHeader: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    padding: "10px 14px",
    borderBottom: "1px solid var(--border)",
    background: "var(--bg-surface)",
  },
  oosPanelTitle: {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "var(--text-muted)",
    letterSpacing: "0.15em",
    flex: 1,
  },
  oosStatsBadge: {
    fontFamily: "var(--font-mono)",
    fontSize: 11,
  },
  oosClearBtn: {
    background: "transparent",
    border: "1px solid var(--border)",
    borderRadius: 3,
    padding: "3px 9px",
    fontFamily: "var(--font-mono)",
    fontSize: 9,
    color: "var(--text-muted)",
    cursor: "pointer",
    letterSpacing: "0.08em",
  },
  oosTextarea: {
    width: "100%",
    minHeight: 100,
    background: "var(--bg-base)",
    border: "none",
    borderBottom: "1px solid var(--border)",
    padding: "12px 14px",
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    color: "var(--text-primary)",
    outline: "none",
    resize: "vertical" as const,
    boxSizing: "border-box" as const,
    lineHeight: 1.6,
  },
  oosFooter: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "8px 14px",
    gap: 10,
  },
  oosHint: {
    fontFamily: "var(--font-mono)",
    fontSize: 9,
    color: "var(--text-muted)",
    opacity: 0.7,
  },
  oosApplyBtn: {
    background: "var(--cyan)",
    color: "var(--bg-base)",
    border: "none",
    borderRadius: 4,
    padding: "6px 14px",
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: "0.08em",
    whiteSpace: "nowrap" as const,
    transition: "opacity 0.15s",
  },
};
