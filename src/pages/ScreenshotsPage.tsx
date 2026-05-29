import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

type IndexEntry = {
  url:     string;
  file:    string | null;
  success: boolean;
  error:   string | null;
};

type ScreenshotsStatus = {
  status:   "not_started" | "running" | "done" | "error";
  total?:   number;
  done?:    number;
  success?: number;
  failed?:  number;
  error?:   string;
  index:    IndexEntry[];
};

const STATUS_COLOR: Record<string, string> = {
  done:        "var(--green)",
  running:     "var(--cyan)",
  error:       "var(--red)",
  not_started: "var(--text-muted)",
};

type ViewMode = "grid" | "list";
type Filter   = "all" | "success" | "failed";

export default function ScreenshotsPage() {
  const [targets, setTargets]   = useState<string[]>([]);
  const [selected, setSelected] = useState("");
  const [data, setData]         = useState<ScreenshotsStatus | null>(null);
  const [loading, setLoading]   = useState(false);
  const [filter, setFilter]     = useState<Filter>("all");
  const [search, setSearch]     = useState("");
  const [viewMode, setViewMode] = useState<ViewMode>("grid");
  const [lightbox, setLightbox] = useState<IndexEntry | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadTargets();
    return () => stopPolling();
  }, []);

  // Close lightbox on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") setLightbox(null);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
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
    const res = await axios.get(`${API}/screenshots/${target}`);
    setData(res.data);
    if (res.data.status === "running") startPolling(target);
  };

  const runCapture = async () => {
    if (!selected) return;
    setLoading(true);
    setData(prev => prev
      ? { ...prev, status: "running", done: 0, index: [] }
      : { status: "running", done: 0, index: [] }
    );
    await axios.post(`${API}/screenshots/${selected}`);
    startPolling(selected);
  };

  const startPolling = (target: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      const res = await axios.get(`${API}/screenshots/${target}`);
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

  const isRunning = loading || data?.status === "running";

  const filtered = (data?.index || []).filter(e => {
    if (filter === "success" && !e.success) return false;
    if (filter === "failed"  && e.success)  return false;
    if (search && !e.url.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const progress = data?.total
    ? Math.round(((data.done || 0) / data.total) * 100)
    : 0;

  return (
    <div>
      {/* Lightbox */}
      {lightbox && (
        <div
          style={s.lightboxOverlay}
          onClick={() => setLightbox(null)}
        >
          <div style={s.lightboxBox} onClick={e => e.stopPropagation()}>
            <div style={s.lightboxHeader}>
              <a
                href={lightbox.url}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "var(--cyan)", fontFamily: "var(--font-mono)", fontSize: 12, textDecoration: "none" }}
              >
                {lightbox.url}
              </a>
              <button onClick={() => setLightbox(null)} style={s.lightboxClose}>✕</button>
            </div>
            <img
              src={`${API}/screenshots/${selected}/img/${lightbox.file}`}
              alt={lightbox.url}
              style={{ width: "100%", display: "block", borderRadius: "0 0 6px 6px" }}
            />
          </div>
        </div>
      )}

      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>PHASE 06</div>
          <h1 style={s.title}>Screenshots</h1>
        </div>
        {data?.success !== undefined && (
          <div style={s.countBox}>
            <span style={s.countNum}>{data.success}</span>
            <span style={s.countLabel}>captured</span>
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
              <div style={s.emptyIcon}>▣</div>
              <div style={s.emptyText}>Select a target to capture screenshots</div>
              <div style={s.emptyHint}>Requires Phase 03 (Live Hosts) to be completed first</div>
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
                    placeholder="Filter by URL..."
                    style={s.searchInput}
                    spellCheck={false}
                  />
                  {search && <button onClick={() => setSearch("")} style={s.clearBtn}>✕</button>}
                </div>

                {/* View mode toggle */}
                <div style={s.viewToggle}>
                  <button
                    onClick={() => setViewMode("grid")}
                    style={{ ...s.viewBtn, ...(viewMode === "grid" ? s.viewBtnActive : {}) }}
                    title="Grid view"
                  >
                    ⊞
                  </button>
                  <button
                    onClick={() => setViewMode("list")}
                    style={{ ...s.viewBtn, ...(viewMode === "list" ? s.viewBtnActive : {}) }}
                    title="List view"
                  >
                    ≡
                  </button>
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
                  onClick={runCapture}
                  disabled={isRunning}
                  style={{
                    ...s.runBtn,
                    opacity: isRunning ? 0.45 : 1,
                    cursor: isRunning ? "not-allowed" : "pointer",
                  }}
                >
                  {isRunning ? "CAPTURING..." : "RUN CAPTURE"}
                </button>
              </div>

              {/* Progress bar while running */}
              {isRunning && data?.total && (
                <div style={s.progressWrap}>
                  <div style={s.progressBar}>
                    <div style={{ ...s.progressFill, width: `${progress}%` }} />
                  </div>
                  <span style={s.progressLabel}>
                    {data.done || 0} / {data.total} — {progress}%
                  </span>
                </div>
              )}

              {/* Stats + filter tabs */}
              {data && data.index.length > 0 && (
                <div style={s.statsRow}>
                  {[
                    { id: "all",     label: "ALL",     count: data.index.length },
                    { id: "success", label: "SUCCESS", count: data.success || 0 },
                    { id: "failed",  label: "FAILED",  count: data.failed  || 0 },
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setFilter(tab.id as Filter)}
                      style={{
                        ...s.filterTab,
                        background: filter === tab.id ? "var(--bg-hover)" : "transparent",
                        color: filter === tab.id
                          ? tab.id === "failed" ? "var(--red)" : "var(--text-primary)"
                          : "var(--text-muted)",
                        borderBottom: filter === tab.id
                          ? `2px solid ${tab.id === "failed" ? "var(--red)" : "var(--cyan)"}`
                          : "2px solid transparent",
                      }}
                    >
                      {tab.label}
                      <span style={s.filterCount}>{tab.count}</span>
                    </button>
                  ))}
                  <span style={s.filteredCount}>
                    {search ? `${filtered.length} shown` : ""}
                  </span>
                </div>
              )}

              {/* Error */}
              {data?.status === "error" && data.error && (
                <div style={s.errorBox}><span>✕</span> {data.error}</div>
              )}

              {/* Not started */}
              {(!data || data.status === "not_started") && !loading && (
                <div style={s.empty}>
                  <div style={s.emptyText}>Click "Run Capture" to screenshot all live hosts</div>
                  <div style={s.emptyHint}>Uses headless Chromium · {CONCURRENCY_DISPLAY} concurrent · 20s timeout per URL</div>
                </div>
              )}

              {/* Grid view */}
              {viewMode === "grid" && filtered.length > 0 && (
                <div style={s.grid}>
                  {filtered.map((entry, i) => (
                    <div
                      key={i}
                      className="animate-in"
                      style={s.card}
                      onClick={() => entry.success && setLightbox(entry)}
                    >
                      <div style={s.cardImg}>
                        {entry.success && entry.file ? (
                          <img
                            src={`${API}/screenshots/${selected}/img/${entry.file}`}
                            alt={entry.url}
                            style={{ width: "100%", height: "100%", objectFit: "cover", display: "block" }}
                            loading="lazy"
                          />
                        ) : (
                          <div style={s.cardNoImg}>
                            <span style={{ fontSize: 22, opacity: 0.3 }}>✕</span>
                            <span style={s.cardErrText}>{entry.error || "failed"}</span>
                          </div>
                        )}
                        {entry.success && (
                          <div style={s.cardHover}>
                            <span style={s.cardHoverIcon}>⊕</span>
                          </div>
                        )}
                      </div>
                      <div style={s.cardUrl}>
                        <a
                          href={entry.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={e => e.stopPropagation()}
                          style={{ color: "var(--cyan)", textDecoration: "none", fontSize: 11 }}
                        >
                          {entry.url.replace(/^https?:\/\//, '')}
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* List view */}
              {viewMode === "list" && filtered.length > 0 && (
                <div style={s.tableWrap}>
                  <table style={s.table}>
                    <thead>
                      <tr>
                        <th style={s.th}>#</th>
                        <th style={s.th}>PREVIEW</th>
                        <th style={s.th}>URL</th>
                        <th style={s.th}>STATUS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((entry, i) => (
                        <tr key={i} className="animate-in">
                          <td style={s.tdIdx}>{String(i + 1).padStart(3, "0")}</td>
                          <td style={s.tdThumb}>
                            {entry.success && entry.file ? (
                              <img
                                src={`${API}/screenshots/${selected}/img/${entry.file}`}
                                alt=""
                                style={{ width: 80, height: 50, objectFit: "cover", borderRadius: 3, cursor: "pointer", display: "block" }}
                                loading="lazy"
                                onClick={() => setLightbox(entry)}
                              />
                            ) : (
                              <div style={{ width: 80, height: 50, background: "var(--bg-surface)", borderRadius: 3, display: "flex", alignItems: "center", justifyContent: "center" }}>
                                <span style={{ fontSize: 16, opacity: 0.3 }}>✕</span>
                              </div>
                            )}
                          </td>
                          <td style={s.tdUrl}>
                            <a
                              href={entry.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ color: "var(--cyan)", textDecoration: "none" }}
                            >
                              {entry.url}
                            </a>
                          </td>
                          <td style={s.tdStatus}>
                            <span style={{
                              fontFamily: "var(--font-mono)", fontSize: 10,
                              color: entry.success ? "var(--green)" : "var(--red)",
                            }}>
                              {entry.success ? "ok" : entry.error || "failed"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {data && data.index.length > 0 && filtered.length === 0 && (
                <div style={s.empty}>
                  <div style={s.emptyText}>No screenshots match filter</div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const CONCURRENCY_DISPLAY = 3;

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
  viewToggle: { display: "flex", gap: 2 },
  viewBtn: {
    padding: "6px 10px", background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 4, color: "var(--text-muted)", cursor: "pointer", fontSize: 14, lineHeight: 1,
  },
  viewBtnActive: { background: "var(--bg-hover)", color: "var(--cyan)", borderColor: "var(--cyan)" },
  badge: { display: "flex", alignItems: "center", gap: 6, padding: "6px 12px", borderRadius: 4, fontFamily: "var(--font-mono)", fontSize: 11, whiteSpace: "nowrap" as const },
  badgeDot: { width: 6, height: 6, borderRadius: "50%", flexShrink: 0 },
  runBtn: {
    background: "var(--cyan)", color: "var(--bg-base)", border: "none", borderRadius: 5,
    padding: "9px 16px", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700,
    letterSpacing: "0.08em", whiteSpace: "nowrap" as const, transition: "opacity 0.15s",
  },
  progressWrap: { marginBottom: 14 },
  progressBar: {
    height: 4, background: "var(--bg-surface)", borderRadius: 2, overflow: "hidden", marginBottom: 6,
  },
  progressFill: {
    height: "100%", background: "var(--cyan)",
    borderRadius: 2, transition: "width 0.4s ease",
    boxShadow: "0 0 8px var(--cyan)",
  },
  progressLabel: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
  statsRow: {
    display: "flex", alignItems: "center", gap: 2,
    borderBottom: "1px solid var(--border)", marginBottom: 14,
  },
  filterTab: {
    padding: "8px 16px", background: "transparent", border: "none",
    cursor: "pointer", fontFamily: "var(--font-mono)", fontSize: 11,
    letterSpacing: "0.08em", display: "flex", alignItems: "center", gap: 8,
    transition: "all 0.15s",
  },
  filterCount: {
    padding: "1px 6px", borderRadius: 3, fontSize: 9,
    background: "var(--bg-hover)", color: "var(--text-muted)",
  },
  filteredCount: { marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
  errorBox: {
    display: "flex", alignItems: "center", gap: 10, padding: "12px 16px",
    background: "rgba(239,68,68,0.08)", border: "1px solid var(--red)",
    borderRadius: 6, color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 12, marginBottom: 14,
  },
  empty: { display: "flex", flexDirection: "column", alignItems: "center", padding: "64px 0", gap: 8 },
  emptyIcon: { fontSize: 30, color: "var(--border-bright)", marginBottom: 8 },
  emptyText: { fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--text-muted)" },
  emptyHint: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", opacity: 0.6 },
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
    gap: 12,
  },
  card: {
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, overflow: "hidden", cursor: "pointer",
    transition: "border-color 0.15s",
  },
  cardImg: {
    position: "relative" as const, width: "100%", height: 140,
    background: "var(--bg-surface)", overflow: "hidden",
  },
  cardNoImg: {
    width: "100%", height: "100%", display: "flex",
    flexDirection: "column" as const, alignItems: "center", justifyContent: "center", gap: 6,
  },
  cardErrText: { fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" },
  cardHover: {
    position: "absolute" as const, inset: 0,
    background: "rgba(0,0,0,0.4)", display: "flex",
    alignItems: "center", justifyContent: "center",
    opacity: 0, transition: "opacity 0.15s",
  },
  cardHoverIcon: { fontSize: 28, color: "white" },
  cardUrl: {
    padding: "8px 10px",
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap" as const,
    borderTop: "1px solid var(--border)",
  },
  tableWrap: { border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" },
  table: { width: "100%", borderCollapse: "collapse" },
  th: {
    padding: "10px 14px", background: "var(--bg-surface)", borderBottom: "1px solid var(--border)",
    fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
    color: "var(--text-muted)", letterSpacing: "0.12em", textAlign: "left" as const,
  },
  tdIdx: {
    padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 10,
    color: "var(--text-muted)", borderBottom: "1px solid var(--border)",
    width: 50, background: "var(--bg-panel)",
  },
  tdThumb: { padding: "8px 14px", borderBottom: "1px solid var(--border)", width: 110 },
  tdUrl: {
    padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 11,
    borderBottom: "1px solid var(--border)", wordBreak: "break-all" as const,
  },
  tdStatus: { padding: "10px 14px", borderBottom: "1px solid var(--border)", width: 100 },
  lightboxOverlay: {
    position: "fixed" as const, inset: 0,
    background: "rgba(0,0,0,0.85)", zIndex: 1000,
    display: "flex", alignItems: "center", justifyContent: "center",
    padding: 32,
  },
  lightboxBox: {
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 8, overflow: "hidden",
    maxWidth: 1100, width: "100%", maxHeight: "90vh", overflowY: "auto" as const,
  },
  lightboxHeader: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "12px 16px", borderBottom: "1px solid var(--border)",
    background: "var(--bg-surface)",
  },
  lightboxClose: {
    background: "transparent", border: "none",
    color: "var(--text-muted)", cursor: "pointer",
    fontSize: 16, padding: "2px 6px",
  },
};
