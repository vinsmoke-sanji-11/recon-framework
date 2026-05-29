import { useEffect, useState } from "react";
import axios from "axios";

const API = "http://localhost:8000/api";

const STATUS_COLOR: Record<string, string> = {
  completed: "var(--green)",
  running:   "var(--cyan)",
  failed:    "var(--red)",
  unknown:   "var(--text-muted)",
};

export default function TargetsPage() {
  const [targets, setTargets]   = useState<string[]>([]);
  const [newTarget, setNewTarget] = useState("");
  const [statuses, setStatuses] = useState<Record<string, string>>({});
  const [scanning, setScanning] = useState(false);

  useEffect(() => { loadTargets(); }, []);

  const loadTargets = async () => {
    try {
      const res = await axios.get(`${API}/targets`);
      const list: string[] = res.data || [];
      setTargets(list);
      list.forEach(async (t) => {
        const s = await axios.get(`${API}/status/${t}`);
        setStatuses(prev => ({ ...prev, [t]: s.data.status }));
      });
    } catch (err) { console.error(err); }
  };

  const handleScan = async () => {
    if (!newTarget.trim()) return;
    setScanning(true);
    try {
      await axios.post(`${API}/scan`, { target: newTarget.trim() });
      setNewTarget("");
      setTimeout(loadTargets, 400);
    } finally { setScanning(false); }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleScan();
  };

  return (
    <div>
      {/* Header */}
      <div style={s.header}>
        <div>
          <div style={s.phase}>RECONNAISSANCE</div>
          <h1 style={s.title}>Targets</h1>
        </div>
        <div style={s.countBox}>
          <span style={s.countNum}>{targets.length}</span>
          <span style={s.countLabel}>targets</span>
        </div>
      </div>

      {/* Input */}
      <div style={s.inputRow}>
        <div style={s.inputBox}>
          <span style={s.prompt}>$</span>
          <input
            value={newTarget}
            onChange={e => setNewTarget(e.target.value)}
            onKeyDown={handleKey}
            placeholder="target.domain.com"
            style={s.input}
            spellCheck={false}
          />
        </div>
        <button
          onClick={handleScan}
          disabled={scanning || !newTarget.trim()}
          style={{
            ...s.btn,
            opacity: (scanning || !newTarget.trim()) ? 0.45 : 1,
            cursor:  (scanning || !newTarget.trim()) ? "not-allowed" : "pointer",
          }}
        >
          {scanning ? "STARTING..." : "START SCAN"}
        </button>
      </div>

      <div style={s.divider} />

      {/* List */}
      {targets.length === 0 ? (
        <div style={s.empty}>
          <div style={s.emptyIcon}>◈</div>
          <div style={s.emptyText}>No targets added yet</div>
          <div style={s.emptyHint}>Enter a domain above to begin</div>
        </div>
      ) : (
        <div style={s.list}>
          {targets.map((t, i) => {
            const status = statuses[t] || "unknown";
            const color  = STATUS_COLOR[status] || STATUS_COLOR.unknown;
            return (
              <div key={t} className="animate-in" style={s.row}>
                <span style={s.rowIdx}>{String(i + 1).padStart(2, "0")}</span>
                <span style={s.rowDomain}>{t}</span>
                <span style={s.rowStatus}>
                  <span
                    style={{ ...s.dot, background: color, boxShadow: `0 0 6px ${color}` }}
                    className={status === "running" ? "pulse" : ""}
                  />
                  <span style={{ ...s.statusText, color }}>{status}</span>
                </span>
              </div>
            );
          })}
        </div>
      )}
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
    color: "var(--text-primary)",
    letterSpacing: "-0.02em",
  },
  countBox: {
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-end",
  },
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
    letterSpacing: "0.1em",
  },
  inputRow: {
    display: "flex",
    gap: 10,
    marginBottom: 20,
  },
  inputBox: {
    flex: 1,
    display: "flex",
    alignItems: "center",
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    padding: "0 14px",
    gap: 10,
  },
  prompt: {
    fontFamily: "var(--font-mono)",
    color: "var(--cyan)",
    fontSize: 14,
    userSelect: "none" as const,
  },
  input: {
    flex: 1,
    background: "transparent",
    border: "none",
    outline: "none",
    color: "var(--text-primary)",
    fontFamily: "var(--font-mono)",
    fontSize: 13,
    padding: "12px 0",
  },
  btn: {
    background: "var(--cyan)",
    color: "var(--bg-base)",
    border: "none",
    borderRadius: 6,
    padding: "0 20px",
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: "0.1em",
    whiteSpace: "nowrap" as const,
    transition: "opacity 0.15s",
  },
  divider: {
    height: 1,
    background: "var(--border)",
    marginBottom: 20,
  },
  empty: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    padding: "64px 0",
    gap: 8,
  },
  emptyIcon: { fontSize: 30, color: "var(--border-bright)", marginBottom: 8 },
  emptyText: { color: "var(--text-secondary)", fontSize: 14 },
  emptyHint: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
  list: { display: "flex", flexDirection: "column", gap: 6 },
  row: {
    display: "flex",
    alignItems: "center",
    gap: 16,
    padding: "13px 16px",
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 6,
  },
  rowIdx: {
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    color: "var(--text-muted)",
    width: 22,
    flexShrink: 0,
  },
  rowDomain: {
    flex: 1,
    fontFamily: "var(--font-mono)",
    fontSize: 13,
    color: "var(--text-primary)",
  },
  rowStatus: {
    display: "flex",
    alignItems: "center",
    gap: 7,
  },
  dot: {
    display: "inline-block",
    width: 7,
    height: 7,
    borderRadius: "50%",
    flexShrink: 0,
  },
  statusText: {
    fontFamily: "var(--font-mono)",
    fontSize: 11,
    letterSpacing: "0.04em",
  },
};
