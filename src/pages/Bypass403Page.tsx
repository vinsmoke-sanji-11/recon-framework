// src/pages/Bypass403Page.tsx

import { useEffect, useRef, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

// ─── Types ────────────────────────────────────────────────────────────────────

type Technique = "header" | "path" | "method";

type Attempt = {
  technique: Technique;
  label:     string;   // human name e.g. "X-Forwarded-For: 127.0.0.1"
  detail:    string;   // exact value: headers string, path variant, method name
  path:      string;
  method:    string;
  status:    number | null;
  success:   boolean;
  curl:      string;
};

type UrlResult = {
  url:        string;
  host:       string;
  origin_ip:  string | null;
  via_origin: boolean;
  bypassed:   boolean;
  done:       boolean;
  attempts:   Attempt[];
  winning:    Attempt | null;
};

type ScanStatus = {
  status:        "not_started" | "running" | "done" | "error";
  total?:        number;
  done?:         number;
  bypassed?:     number;
  held?:         number;
  viaOrigin?:    number;
  viaCDN?:       number;
  totalAttempts?: number;
  error?:        string;
  completedAt?:  string;
  results:       UrlResult[];
};

// ─── Colours ──────────────────────────────────────────────────────────────────

const TC: Record<Technique, { fg: string; bg: string; label: string }> = {
  header: { fg: "#a855f7", bg: "rgba(168,85,247,.13)", label: "IP SPOOF" },
  path:   { fg: "#3b82f6", bg: "rgba(59,130,246,.13)",  label: "PATH" },
  method: { fg: "#f97316", bg: "rgba(249,115,22,.13)",  label: "METHOD" },
};

function statusColor(s: number | null) {
  if (s === 200) return "#22c55e";
  if (s === 403) return "#ef4444";
  if (s === 404) return "#6b7280";
  if (s === null) return "#374151";
  return "#eab308";
}

// ─── Subcomponents ────────────────────────────────────────────────────────────

function AttemptRow({ a, idx }: { a: Attempt; idx: number }) {
  const [open, setOpen] = useState(false);
  const tc = TC[a.technique];
  return (
    <div style={{
      borderBottom: "1px solid var(--border)",
      background: a.success ? "rgba(34,197,94,.05)" : idx % 2 === 0 ? "transparent" : "rgba(255,255,255,.01)",
    }}>
      {/* Row */}
      <div
        onClick={() => setOpen(o => !o)}
        style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", cursor: "pointer" }}
      >
        {/* status badge */}
        <span style={{
          fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700,
          color: statusColor(a.status),
          minWidth: 36, textAlign: "right",
        }}>
          {a.status ?? "—"}
        </span>

        {/* technique pill */}
        <span style={{
          ...pill, background: tc.bg, color: tc.fg,
          minWidth: 54, textAlign: "center",
        }}>
          {tc.label}
        </span>

        {/* label */}
        <span style={{ flex: 1, fontFamily: "var(--font-mono)", fontSize: 11, color: a.success ? "#22c55e" : "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {a.label}
        </span>

        {/* success badge */}
        {a.success && (
          <span style={{ ...pill, background: "rgba(34,197,94,.15)", color: "#22c55e", border: "1px solid rgba(34,197,94,.3)" }}>
            ✓ BYPASSED
          </span>
        )}

        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)" }}>{open ? "▲" : "▼"}</span>
      </div>

      {/* Expanded detail */}
      {open && (
        <div style={{ padding: "8px 14px 10px 66px", display: "flex", flexDirection: "column", gap: 8, borderTop: "1px solid var(--border)" }}>

          {/* what exactly was sent */}
          <div>
            <div style={detailLabel}>
              {a.technique === "header" ? "HEADERS INJECTED" : a.technique === "path" ? "PATH USED" : "HTTP METHOD"}
            </div>
            <pre style={codeBox}>{a.detail}</pre>
          </div>

          {/* explanation */}
          <div>
            <div style={detailLabel}>HOW IT WORKS</div>
            <div style={explainBox}>
              {a.technique === "header" && "The server trusts IP headers to decide if a request is internal. Spoofing them to 127.0.0.1 makes the server think the request came from localhost and may skip the access check."}
              {a.technique === "path" && "The WAF or server's ACL matches the raw URL path. A manipulated path that resolves to the same resource server-side (e.g. trailing slash, URL encoding, dot-slash) can slip past the rule."}
              {a.technique === "method" && "Access controls sometimes only block specific HTTP methods (GET/POST). Sending an alternative method that the server still handles (PUT, OPTIONS, TRACE etc.) may return the resource."}
            </div>
          </div>

          {/* curl */}
          <div>
            <div style={detailLabel}>CURL TO REPRODUCE</div>
            <pre style={{ ...codeBox, color: "#22c55e" }}>{a.curl}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

function UrlCard({ r, defaultOpen }: { r: UrlResult; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(!!defaultOpen);
  const [techFilter, setTechFilter] = useState<"all" | Technique>("all");

  const shown = r.attempts.filter(a => techFilter === "all" || a.technique === techFilter);
  const counts = {
    header: r.attempts.filter(a => a.technique === "header").length,
    path:   r.attempts.filter(a => a.technique === "path").length,
    method: r.attempts.filter(a => a.technique === "method").length,
  };

  return (
    <div style={{
      border: `1px solid ${r.bypassed ? "rgba(34,197,94,.4)" : "var(--border)"}`,
      borderLeft: `3px solid ${r.bypassed ? "#22c55e" : r.done ? "#6b7280" : "var(--cyan)"}`,
      borderRadius: 6,
      background: r.bypassed ? "rgba(34,197,94,.03)" : "var(--bg-panel)",
      marginBottom: 6,
    }}>
      {/* Header row */}
      <div onClick={() => setOpen(o => !o)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", cursor: "pointer" }}>

        {/* result */}
        <span style={{
          ...pill,
          background: r.bypassed ? "rgba(34,197,94,.15)" : r.done ? "rgba(107,114,128,.12)" : "rgba(59,130,246,.12)",
          color: r.bypassed ? "#22c55e" : r.done ? "#9ca3af" : "var(--cyan)",
          border: `1px solid ${r.bypassed ? "rgba(34,197,94,.3)" : "rgba(107,114,128,.2)"}`,
          minWidth: 72, textAlign: "center",
        }}>
          {r.bypassed ? "✓ BYPASSED" : r.done ? "✗ HELD" : "⏳ TESTING"}
        </span>

        {/* URL */}
        <span style={{ flex: 1, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {r.url}
        </span>

        {/* attempt count */}
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
          {r.attempts.length} attempts
        </span>

        {/* origin IP badge */}
        {r.origin_ip && (
          <span style={{ ...pill, background: "rgba(59,130,246,.1)", color: "var(--cyan)" }}>
            → {r.origin_ip}
          </span>
        )}

        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)" }}>{open ? "▲" : "▼"}</span>
      </div>

      {/* Winning technique banner */}
      {r.bypassed && r.winning && !open && (
        <div style={{ padding: "0 12px 10px" }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "#22c55e" }}>
            {TC[r.winning.technique].label}: {r.winning.label}
          </span>
        </div>
      )}

      {/* Expanded attempts */}
      {open && r.attempts.length > 0 && (
        <div style={{ borderTop: "1px solid var(--border)" }}>
          {/* Technique filter tabs */}
          <div style={{ display: "flex", gap: 4, padding: "8px 10px", background: "var(--bg-base)", borderBottom: "1px solid var(--border)" }}>
            {([["all", `All (${r.attempts.length})`], ["header", `Headers (${counts.header})`], ["path", `Path (${counts.path})`], ["method", `Method (${counts.method})`]] as [string, string][]).map(([k, label]) => (
              <button key={k} onClick={e => { e.stopPropagation(); setTechFilter(k as any); }} style={{
                background: techFilter === k ? "var(--bg-surface)" : "transparent",
                border: `1px solid ${techFilter === k ? "var(--border)" : "transparent"}`,
                borderRadius: 4, padding: "3px 8px",
                fontFamily: "var(--font-mono)", fontSize: 9, color: techFilter === k ? "var(--text-primary)" : "var(--text-muted)",
                cursor: "pointer",
              }}>
                {label}
              </button>
            ))}
            <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", alignSelf: "center" }}>
              {r.attempts.filter(a => a.success).length} succeeded
            </span>
          </div>

          {/* Column headers */}
          <div style={{ display: "flex", gap: 8, padding: "4px 10px", background: "var(--bg-base)", borderBottom: "1px solid var(--border)" }}>
            {["STATUS", "TECHNIQUE", "WHAT WAS TRIED", ""].map((h, i) => (
              <span key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 8, color: "var(--text-muted)", letterSpacing: "0.1em",
                minWidth: i === 0 ? 36 : i === 1 ? 54 : i === 2 ? undefined : 62,
                flex: i === 2 ? 1 : undefined, textAlign: i === 0 ? "right" : "left",
              }}>{h}</span>
            ))}
          </div>

          {/* Attempt rows */}
          {shown.map((a, idx) => <AttemptRow key={idx} a={a} idx={idx} />)}
        </div>
      )}

      {open && r.attempts.length === 0 && !r.done && (
        <div style={{ padding: "14px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", textAlign: "center", borderTop: "1px solid var(--border)" }}>
          Waiting to start…
        </div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Bypass403Page() {
  const [targets, setTargets]   = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [data, setData]         = useState<ScanStatus | null>(null);
  const [view, setView]         = useState<"bypassed" | "held" | "all">("all");
  const [search, setSearch]     = useState("");
  const pollRef                 = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    axios.get(`${API}/targets`).then(r => setTargets(r.data.map((t: { target: string }) => t.target)));
  }, []);

  const load = async (t: string) => {
    const r = await axios.get(`${API}/bypass403/${t}`);
    setData(r.data);
    if (r.data.status === "running") poll(t);
  };

  const poll = (t: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      const r = await axios.get(`${API}/bypass403/${t}`);
      setData(r.data);
      if (r.data.status !== "running") { clearInterval(pollRef.current!); pollRef.current = null; }
    }, 2500);
  };

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const selectTarget = (t: string) => { setSelected(t); setData(null); load(t); };
  const run = async () => {
    if (!selected) return;
    await axios.post(`${API}/bypass403/${selected}`);
    await load(selected);
  };

  const results = data?.results ?? [];
  const filtered = results.filter(r => {
    const matchView   = view === "all" || (view === "bypassed" ? r.bypassed : r.done && !r.bypassed);
    const matchSearch = !search || r.url.toLowerCase().includes(search.toLowerCase());
    return matchView && matchSearch;
  });

  const total    = data?.total    ?? 0;
  const done     = data?.done     ?? 0;
  const bypassed = data?.bypassed ?? 0;
  const progress = total > 0 ? Math.round((done / total) * 100) : 0;

  return (
    <div style={{ display: "flex", height: "100%", background: "var(--bg-base)", overflow: "hidden" }}>

      {/* Sidebar */}
      <div style={{ width: 210, minWidth: 210, background: "var(--bg-panel)", borderRight: "1px solid var(--border)", overflowY: "auto", display: "flex", flexDirection: "column" }}>

        <div style={sideSection}>
          <div style={sideLabel}>TARGETS</div>
          {targets.map(t => (
            <button key={t} onClick={() => selectTarget(t)} style={{ ...targetBtn, ...(selected === t ? targetBtnActive : {}) }}>
              {t}
            </button>
          ))}
          {!targets.length && <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", opacity: .5 }}>No targets</div>}
        </div>

        {/* How it works */}
        <div style={sideSection}>
          <div style={sideLabel}>TECHNIQUES (IN ORDER)</div>
          {[
            ["1", "IP SPOOF", "#a855f7", "18 header variants injected. Tricks server into treating request as internal (127.0.0.1)."],
            ["2", "PATH", "#3b82f6", "16 path variants. Trailing slash, URL encoding, dot-slash, null byte, semicolons etc."],
            ["3", "METHOD", "#f97316", "7 HTTP methods. POST, PUT, PATCH, OPTIONS, TRACE, HEAD, DELETE."],
          ].map(([n, name, color, desc]) => (
            <div key={n as string} style={{ marginBottom: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", background: "var(--bg-surface)", borderRadius: 3, padding: "1px 5px" }}>{n}</span>
                <span style={{ ...pill, background: `${color}20`, color: color as string }}>{name}</span>
              </div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", lineHeight: 1.5, paddingLeft: 4 }}>{desc}</div>
            </div>
          ))}
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", lineHeight: 1.5, marginTop: 4, paddingTop: 6, borderTop: "1px solid var(--border)" }}>
            Stops at first success per URL. All attempts logged regardless.
          </div>
        </div>

        {/* Stats */}
        {data && data.status !== "not_started" && (
          <div style={sideSection}>
            <div style={sideLabel}>RESULTS</div>
            {[
              ["Total URLs",     total],
              ["Tested",         done],
              ["Bypassed",       bypassed],
              ["Held",           data.held ?? (done - bypassed)],
              ["Via origin IP",  data.viaOrigin ?? 0],
              ["Via CDN",        data.viaCDN    ?? 0],
              ["Total attempts", data.totalAttempts ?? "—"],
            ].map(([l, v]) => (
              <div key={l as string} style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>{l}</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: l === "Bypassed" && (v as number) > 0 ? "#22c55e" : "var(--text-primary)", fontWeight: l === "Bypassed" ? 700 : 400 }}>{v}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Main */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {!selected ? (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 8 }}>
            <div style={{ fontSize: 32, opacity: .4 }}>🔓</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)", letterSpacing: "0.15em" }}>403 BYPASS ENGINE</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", opacity: .6 }}>Select a target — requires Confidential scan first</div>
          </div>
        ) : (
          <>
            {/* Toolbar */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Filter by URL…" style={{ flex: 1, background: "var(--bg-base)", border: "1px solid var(--border)", borderRadius: 4, padding: "5px 9px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-primary)", outline: "none" }} />

              {/* View toggle */}
              <div style={{ display: "flex", border: "1px solid var(--border)", borderRadius: 4, overflow: "hidden" }}>
                {([["all", "ALL"], ["bypassed", "BYPASSED"], ["held", "HELD"]] as [string, string][]).map(([k, label]) => (
                  <button key={k} onClick={() => setView(k as any)} style={{
                    background: view === k ? "var(--bg-surface)" : "transparent",
                    border: "none", borderRight: k !== "held" ? "1px solid var(--border)" : "none",
                    padding: "5px 10px", fontFamily: "var(--font-mono)", fontSize: 9, letterSpacing: "0.06em",
                    color: view === k ? (k === "bypassed" ? "#22c55e" : k === "held" ? "#ef4444" : "var(--text-primary)") : "var(--text-muted)",
                    cursor: "pointer",
                  }}>
                    {label}
                    {data && k === "bypassed" && bypassed > 0 && <span style={{ marginLeft: 5, background: "rgba(34,197,94,.15)", color: "#22c55e", borderRadius: 3, padding: "0 4px", fontSize: 9 }}>{bypassed}</span>}
                    {data && k === "held" && (done - bypassed) > 0 && <span style={{ marginLeft: 5, background: "rgba(239,68,68,.1)", color: "#ef4444", borderRadius: 3, padding: "0 4px", fontSize: 9 }}>{done - bypassed}</span>}
                  </button>
                ))}
              </div>

              {/* Status */}
              <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: data?.status === "running" ? "var(--cyan)" : data?.status === "done" ? "#22c55e" : "var(--text-muted)", animation: data?.status === "running" ? "pulse 1.5s infinite" : "none" }} />
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
                  {data?.status === "running" ? `${done}/${total}` : data?.status ?? "not started"}
                </span>
              </div>

              <button onClick={run} disabled={data?.status === "running"} style={{
                background: "var(--cyan)", color: "var(--bg-base)", border: "none", borderRadius: 4,
                padding: "6px 14px", fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700,
                cursor: data?.status === "running" ? "not-allowed" : "pointer", opacity: data?.status === "running" ? .5 : 1,
              }}>
                {data?.status === "running" ? "RUNNING…" : "RUN BYPASS"}
              </button>
            </div>

            {/* Progress bar */}
            {data?.status === "running" && (
              <div style={{ height: 2, background: "var(--bg-surface)" }}>
                <div style={{ height: "100%", background: "var(--cyan)", width: `${progress}%`, transition: "width .4s" }} />
              </div>
            )}

            {/* Content */}
            <div style={{ flex: 1, overflowY: "auto", padding: 12 }}>

              {data?.status === "error" && (
                <div style={{ textAlign: "center", paddingTop: 60, fontFamily: "var(--font-mono)", fontSize: 11, color: "#ef4444" }}>
                  ⚠ {data.error}
                </div>
              )}

              {(!data || data.status === "not_started") && (
                <div style={{ textAlign: "center", paddingTop: 60, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                  Click RUN BYPASS to start
                </div>
              )}

              {data?.status === "running" && results.length === 0 && (
                <div style={{ textAlign: "center", paddingTop: 60, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                  Starting…
                </div>
              )}

              {filtered.length > 0 && filtered.map((r, i) => (
                <UrlCard key={r.url + i} r={r} defaultOpen={r.bypassed} />
              ))}

              {data?.status === "done" && filtered.length === 0 && (
                <div style={{ textAlign: "center", paddingTop: 60, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                  {view === "bypassed" ? "No bypasses found — all 403s held" : "No results match filter"}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ─── Shared styles ────────────────────────────────────────────────────────────
const pill: React.CSSProperties = {
  borderRadius: 3, padding: "2px 7px",
  fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700, letterSpacing: "0.06em",
  whiteSpace: "nowrap",
};
const sideSection: React.CSSProperties = {
  padding: "12px 11px 10px", borderBottom: "1px solid var(--border)",
};
const sideLabel: React.CSSProperties = {
  fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.14em", marginBottom: 8,
};
const targetBtn: React.CSSProperties = {
  display: "block", width: "100%", textAlign: "left", background: "transparent",
  border: "none", borderRadius: 4, padding: "5px 7px",
  fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)", cursor: "pointer", marginBottom: 2,
};
const targetBtnActive: React.CSSProperties = {
  background: "var(--bg-surface)", color: "var(--cyan)",
  borderLeft: "2px solid var(--cyan)", paddingLeft: 5,
};
const detailLabel: React.CSSProperties = {
  fontFamily: "var(--font-mono)", fontSize: 8, color: "var(--text-muted)", letterSpacing: "0.12em", marginBottom: 4,
};
const codeBox: React.CSSProperties = {
  background: "var(--bg-base)", border: "1px solid var(--border)", borderRadius: 4,
  padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--cyan)",
  whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.6, margin: 0,
};
const explainBox: React.CSSProperties = {
  background: "var(--bg-base)", border: "1px solid var(--border)", borderRadius: 4,
  padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-secondary)",
  lineHeight: 1.7,
};
