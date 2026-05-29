import { useEffect, useRef, useState, useCallback } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";
const PAGE_SIZE = 200;

const TOOL_LABELS: Record<string, string> = {
  gau:         "GAU",
  gospider:    "GoSpider",
  katana:      "Katana",
  waybackurls: "WaybackURLs",
};

const TOOL_ORDER = ["gau", "waybackurls", "gospider", "katana"];

type URLsStatus = {
  status: "not_started" | "running" | "done" | "timeout" | "error";
  totalURLs?:     number;
  uniqueDomains?: number;
  toolCounts?:    Record<string, number>;
  tools?:         Record<string, string>;
  error?: string;
  urls:           string[];
  totalFiltered?: number;
  page?:          number;
  limit?:         number;
};

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  timeout:     "var(--orange)",
  error:       "var(--red)",
  not_started: "var(--text-muted)",
};

// Category definitions
const CATEGORIES: {
  id: string;
  label: string;
  color: string;
  test: (url: string) => boolean;
}[] = [
  {
    id: "auth",
    label: "AUTH",
    color: "var(--red)",
    test: u => /\/(admin|login|logout|auth|oauth|signup|register|password|forgot|reset|session|token|sso|saml|2fa|mfa)/i.test(u),
  },
  {
    id: "api",
    label: "API",
    color: "var(--green)",
    test: u => /\/(api|graphql|rest|v\d+|swagger|openapi|endpoint|rpc|grpc)\//i.test(u),
  },
  {
    id: "params",
    label: "PARAMS",
    color: "var(--cyan)",
    test: u => /\?.*=.+/.test(u),
  },
  {
    id: "js",
    label: "JS",
    color: "#a78bfa",
    test: u => /\.(js|ts|jsx|tsx|mjs|cjs)(\?|$)/.test(u),
  },
  {
    id: "data",
    label: "DATA",
    color: "var(--orange)",
    test: u => /\.(json|xml|yaml|yml|csv|pdf|doc|docx|xls|xlsx|zip|tar|gz|sql|bak|config|env)(\?|$)/.test(u),
  },
];

function urlColor(url: string): string {
  for (const cat of CATEGORIES) {
    if (cat.test(url)) return cat.color;
  }
  return "var(--text-secondary)";
}

function toolColor(val: string) {
  if (val === "running")           return "var(--cyan)";
  if (val === "done")              return "var(--green)";
  if (val === "timeout")           return "var(--orange)";
  if (val?.startsWith("skipped")) return "var(--text-muted)";
  return "var(--text-muted)";
}

function toolIcon(val: string) {
  if (val === "running")           return "◌";
  if (val === "done")              return "●";
  if (val === "timeout")           return "◎";
  if (val?.startsWith("skipped")) return "◌";
  return "○";
}

export default function URLsPage() {
  const [targets, setTargets]         = useState<string[]>([]);
  const [selected, setSelected]       = useState("");
  const [data, setData]               = useState<URLsStatus | null>(null);
  const [loading, setLoading]         = useState(false);
  const [filter, setFilter]           = useState("");
  const [debouncedFilter, setDebouncedFilter] = useState("");
  const [page, setPage]               = useState(0);
  const [activeCategories, setActiveCategories] = useState<Set<string>>(new Set());
  const pollRef     = useRef<ReturnType<typeof setInterval> | null>(null);
  const filterTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // All URLs for client-side category filtering
  const [allURLs, setAllURLs] = useState<string[]>([]);

  useEffect(() => {
    loadTargets();
    return () => stopPolling();
  }, []);

  // Debounce text filter
  useEffect(() => {
    if (filterTimer.current) clearTimeout(filterTimer.current);
    filterTimer.current = setTimeout(() => {
      setDebouncedFilter(filter);
      setPage(0);
    }, 300);
  }, [filter]);

  const loadTargets = async () => {
    const res = await axios.get(`${API}/targets`);
    setTargets(res.data || []);
  };

  // Fetch all URLs once for category filtering (no server pagination when categories active)
  const fetchAllURLs = useCallback(async (target: string) => {
    const res = await axios.get(`${API}/urls/${target}`, {
      params: { page: 0, limit: 999999 },
    });
    setAllURLs(res.data.urls || []);
    return res.data;
  }, []);

  const fetchPage = useCallback(async (target: string, pg: number, flt: string) => {
    const res = await axios.get(`${API}/urls/${target}`, {
      params: { page: pg, limit: PAGE_SIZE, filter: flt },
    });
    return res.data;
  }, []);

  const selectTarget = async (target: string) => {
    stopPolling();
    setSelected(target);
    setData(null);
    setFilter("");
    setDebouncedFilter("");
    setPage(0);
    setActiveCategories(new Set());
    setAllURLs([]);
    const res = await fetchPage(target, 0, "");
    setData(res);
    if (res.status === "done") fetchAllURLs(target);
    if (res.status === "running") startPolling(target);
  };

  // Reload page when text filter or page changes (only when no category filter)
  useEffect(() => {
    if (!selected || activeCategories.size > 0) return;
    fetchPage(selected, page, debouncedFilter).then(setData);
  }, [page, debouncedFilter, selected]);

  const toggleCategory = (id: string) => {
    setActiveCategories(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
    setPage(0);
  };

  const runDiscovery = async () => {
    if (!selected) return;
    setLoading(true);
    setAllURLs([]);
    setData(prev => prev
      ? { ...prev, status: "running", urls: [] }
      : { status: "running", urls: [] }
    );
    await axios.post(`${API}/urls/${selected}`);
    startPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const res = await fetchPage(target, 0, "");
      setData(res);
      if (res.status !== "running") {
        stopPolling();
        setLoading(false);
        if (res.status === "done") fetchAllURLs(target);
      }
    }, 4000);
  };

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const isRunning = loading || data?.status === "running";

  // Category counts from allURLs
  const categoryCounts: Record<string, number> = {};
  for (const cat of CATEGORIES) {
    categoryCounts[cat.id] = allURLs.filter(cat.test).length;
  }

  // Apply category + text filter on client side when categories are active
  const displayURLs = (() => {
    if (activeCategories.size === 0) {
      // Server-paginated
      return { urls: data?.urls || [], total: data?.totalFiltered || 0, isPaginated: true };
    }
    // Client-side filter
    let filtered = allURLs;
    if (activeCategories.size > 0) {
      filtered = filtered.filter(url =>
        [...activeCategories].some(id => CATEGORIES.find(c => c.id === id)?.test(url))
      );
    }
    if (debouncedFilter) {
      filtered = filtered.filter(u => u.toLowerCase().includes(debouncedFilter.toLowerCase()));
    }
    const total     = filtered.length;
    const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    return { urls: paginated, total, isPaginated: false };
  })();

  const totalPages = Math.ceil(displayURLs.total / PAGE_SIZE);

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 05</div>
          <h1 style={s.title}>URL Discovery</h1>
        </div>
        {data?.totalURLs !== undefined && (
          <div style={s.countBox}>
            <span style={s.countNum}>{data.totalURLs.toLocaleString()}</span>
            <span style={s.countLabel}>unique URLs</span>
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
              <div style={s.emptyIcon}>◈</div>
              <div style={s.emptyText}>Select a target to discover URLs</div>
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
                    placeholder="Filter URLs..."
                    style={s.searchInput}
                    spellCheck={false}
                  />
                  {filter && <button onClick={() => setFilter("")} style={s.clearBtn}>✕</button>}
                </div>

                {data && (
                  <div style={{
                    ...s.badge,
                    background: `${STATUS_COLOR[data.status]}22`,
                    border: `1px solid ${STATUS_COLOR[data.status]}`,
                    color: STATUS_COLOR[data.status],
                  }}>
                    <span
                      style={{ ...s.badgeDot, background: STATUS_COLOR[data.status] }}
                      className={isRunning ? "pulse" : ""}
                    />
                    {data.status}
                  </div>
                )}

                <button
                  onClick={runDiscovery}
                  disabled={isRunning}
                  style={{
                    ...s.runBtn,
                    opacity: isRunning ? 0.45 : 1,
                    cursor: isRunning ? "not-allowed" : "pointer",
                  }}
                >
                  {isRunning ? "CRAWLING..." : "RUN DISCOVERY"}
                </button>
              </div>

              {/* Tool status panel */}
              {data?.tools && Object.keys(data.tools).length > 0 && (
                <div style={s.toolPanel}>
                  <div style={s.toolPanelHeader}>
                    <span style={s.toolPanelTitle}>DISCOVERY TOOLS</span>
                    {isRunning && <span style={{ ...s.toolBadge, color: "var(--cyan)" }} className="pulse">RUNNING</span>}
                    {data.status === "done" && <span style={{ ...s.toolBadge, color: "var(--green)" }}>COMPLETE</span>}
                  </div>
                  <div style={s.toolGrid}>
                    {TOOL_ORDER.map(key => {
                      const val   = data.tools?.[key] || "";
                      const color = toolColor(val);
                      const icon  = toolIcon(val);
                      const count = data.toolCounts?.[key];
                      return (
                        <div key={key} style={s.toolRow}>
                          <span style={{ ...s.toolIcon, color }} className={val === "running" ? "pulse" : ""}>{icon}</span>
                          <span style={s.toolName}>{TOOL_LABELS[key]}</span>
                          {count !== undefined && count > 0 && (
                            <span style={s.toolCount}>{count.toLocaleString()}</span>
                          )}
                          <span style={{ ...s.toolStatus, color }}>
                            {val.startsWith("skipped") ? "skipped" : val || "waiting"}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Stats */}
              {data?.totalURLs !== undefined && (
                <div style={s.statsRow}>
                  <div style={s.stat}>
                    <span style={s.statNum}>{data.totalURLs.toLocaleString()}</span>
                    <span style={s.statLabel}>total URLs</span>
                  </div>
                  <div style={s.statDivider} />
                  <div style={s.stat}>
                    <span style={s.statNum}>{data.uniqueDomains}</span>
                    <span style={s.statLabel}>domains</span>
                  </div>
                  {(activeCategories.size > 0 || debouncedFilter) && (
                    <>
                      <div style={s.statDivider} />
                      <div style={s.stat}>
                        <span style={{ ...s.statNum, color: "var(--amber)" }}>{displayURLs.total.toLocaleString()}</span>
                        <span style={s.statLabel}>filtered</span>
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* Category filter tabs */}
              {allURLs.length > 0 && (
                <div style={s.catRow}>
                  <span style={s.catLabel}>FILTER:</span>
                  {CATEGORIES.map(cat => {
                    const active = activeCategories.has(cat.id);
                    const count  = categoryCounts[cat.id] || 0;
                    return (
                      <button
                        key={cat.id}
                        onClick={() => toggleCategory(cat.id)}
                        style={{
                          ...s.catBtn,
                          background: active ? `${cat.color}22` : "var(--bg-panel)",
                          border: `1px solid ${active ? cat.color : "var(--border)"}`,
                          color: active ? cat.color : "var(--text-muted)",
                        }}
                      >
                        <span style={{
                          display: "inline-block",
                          width: 6, height: 6, borderRadius: "50%",
                          background: cat.color, marginRight: 6, flexShrink: 0,
                        }} />
                        {cat.label}
                        <span style={{
                          marginLeft: 6,
                          padding: "0 5px",
                          borderRadius: 3,
                          fontSize: 9,
                          background: active ? `${cat.color}33` : "var(--bg-hover)",
                          color: active ? cat.color : "var(--text-muted)",
                        }}>
                          {count.toLocaleString()}
                        </span>
                      </button>
                    );
                  })}
                  {activeCategories.size > 0 && (
                    <button
                      onClick={() => { setActiveCategories(new Set()); setPage(0); }}
                      style={s.clearCatBtn}
                    >
                      CLEAR
                    </button>
                  )}
                </div>
              )}

              {/* Error */}
              {data?.status === "error" && data.error && (
                <div style={s.errorBox}><span>✕</span> {data.error}</div>
              )}

              {/* Not started */}
              {(!data || data.status === "not_started") && !loading && (
                <div style={s.empty}>
                  <div style={s.emptyText}>Click "Run Discovery" to start URL crawling</div>
                  <div style={s.emptyHint}>Uses GAU, WaybackURLs, GoSpider, and Katana</div>
                </div>
              )}

              {/* URL table */}
              {displayURLs.urls.length > 0 && (
                <>
                  <div style={s.tableWrap}>
                    <table style={s.table}>
                      <thead>
                        <tr>
                          <th style={s.th}>#</th>
                          <th style={s.th}>URL</th>
                        </tr>
                      </thead>
                      <tbody>
                        {displayURLs.urls.map((url, i) => (
                          <tr key={i} className="animate-in">
                            <td style={s.tdIdx}>{String(page * PAGE_SIZE + i + 1).padStart(4, "0")}</td>
                            <td style={s.tdUrl}>
                              <a
                                href={url}
                                target="_blank"
                                rel="noopener noreferrer"
                                style={{ color: urlColor(url), textDecoration: "none" }}
                              >
                                {url}
                              </a>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div style={s.pagination}>
                      <button
                        onClick={() => setPage(p => Math.max(0, p - 1))}
                        disabled={page === 0}
                        style={{ ...s.pageBtn, opacity: page === 0 ? 0.3 : 1 }}
                      >
                        ← PREV
                      </button>
                      <span style={s.pageInfo}>
                        {page + 1} / {totalPages}
                        {" · "}
                        {(page * PAGE_SIZE + 1).toLocaleString()}–{Math.min((page + 1) * PAGE_SIZE, displayURLs.total).toLocaleString()}
                        {" of "}
                        {displayURLs.total.toLocaleString()}
                      </span>
                      <button
                        onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                        disabled={page >= totalPages - 1}
                        style={{ ...s.pageBtn, opacity: page >= totalPages - 1 ? 0.3 : 1 }}
                      >
                        NEXT →
                      </button>
                    </div>
                  )}
                </>
              )}

              {data?.status === "done" && displayURLs.urls.length === 0 && (
                <div style={s.empty}>
                  <div style={s.emptyText}>
                    {activeCategories.size > 0 || debouncedFilter ? "No URLs match filter" : "No URLs found"}
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
  toolPanel: { background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden", marginBottom: 14 },
  toolPanelHeader: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-surface)",
  },
  toolPanelTitle: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.15em" },
  toolBadge: { fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.1em" },
  toolGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", padding: "6px 0" },
  toolRow: { display: "flex", alignItems: "center", gap: 8, padding: "7px 14px" },
  toolIcon: { fontSize: 12, width: 14, textAlign: "center" as const, flexShrink: 0 },
  toolName: { flex: 1, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" },
  toolCount: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--cyan)", marginRight: 4 },
  toolStatus: { fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: "0.04em" },
  statsRow: {
    display: "flex", alignItems: "center", gap: 20, padding: "12px 16px",
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, marginBottom: 14, flexWrap: "wrap" as const,
  },
  stat: { display: "flex", alignItems: "baseline", gap: 8 },
  statNum: { fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 700, color: "var(--cyan)" },
  statLabel: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
  statDivider: { width: 1, height: 24, background: "var(--border)" },
  catRow: {
    display: "flex", alignItems: "center", gap: 8,
    marginBottom: 14, flexWrap: "wrap" as const,
  },
  catLabel: {
    fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)",
    letterSpacing: "0.15em", marginRight: 4,
  },
  catBtn: {
    display: "inline-flex", alignItems: "center",
    padding: "5px 12px", borderRadius: 4,
    fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600,
    cursor: "pointer", letterSpacing: "0.06em",
    transition: "all 0.15s",
  },
  clearCatBtn: {
    padding: "5px 10px", borderRadius: 4,
    background: "transparent", border: "1px solid var(--border)",
    fontFamily: "var(--font-mono)", fontSize: 10,
    color: "var(--text-muted)", cursor: "pointer",
    letterSpacing: "0.08em", marginLeft: 4,
  },
  errorBox: {
    display: "flex", alignItems: "center", gap: 10, padding: "12px 16px",
    background: "rgba(239,68,68,0.08)", border: "1px solid var(--red)",
    borderRadius: 6, color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 14,
  },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", padding: "64px 0", gap: 8 },
  emptyIcon: { fontSize: 30, color: "var(--border-bright)", marginBottom: 8 },
  emptyText: { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-muted)" },
  emptyHint: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", opacity: 0.6 },
  tableWrap: { border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" },
  table: { width: "100%", borderCollapse: "collapse" },
  th: {
    padding: "10px 14px", background: "var(--bg-surface)", borderBottom: "1px solid var(--border)",
    fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
    color: "var(--text-muted)", letterSpacing: "0.12em", textAlign: "left" as const,
  },
  tdIdx: {
    padding: "7px 14px", fontFamily: "var(--font-mono)", fontSize: 10,
    color: "var(--text-muted)", borderBottom: "1px solid var(--border)",
    width: 60, background: "var(--bg-panel)", userSelect: "none" as const,
  },
  tdUrl: {
    padding: "7px 14px", fontFamily: "var(--font-mono)", fontSize: 11,
    borderBottom: "1px solid var(--border)", wordBreak: "break-all" as const,
  },
  pagination: {
    display: "flex", alignItems: "center", justifyContent: "center",
    gap: 16, padding: "16px 0",
  },
  pageBtn: {
    background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 4,
    padding: "6px 14px", fontFamily: "var(--font-mono)", fontSize: 11,
    color: "var(--text-secondary)", cursor: "pointer", letterSpacing: "0.06em",
  },
  pageInfo: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
};
