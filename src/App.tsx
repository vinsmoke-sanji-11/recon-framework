import { useState } from "react";
import TargetsPage from "./pages/TargetsPage";
import SubdomainsPage from "./pages/SubdomainsPage";
import DNSPage from "./pages/DNSPage";
import LivePage from "./pages/LivePage";
import PortsPage from "./pages/PortsPage";
import URLsPage from "./pages/URLsPage";
import ScreenshotsPage from "./pages/ScreenshotsPage";
import ConfidentialPage from "./pages/ConfidentialPage";
import OriginIPPage from "./pages/OriginIPPage";
import IntelligencePage from "./pages/IntelligencePage";
import NucleiPage from "./pages/NucleiPage";

type Page = "targets"|"subdomains"|"dns"|"live"|"ports"|"urls"|"screenshots"|"confidential"|"originip"|"intelligence"|"nuclei";

const NAV: { id: Page; label: string; phase?: string; icon: string }[] = [
  { id: "targets",      label: "Targets",      icon: "◈" },
  { id: "subdomains",   label: "Subdomains",   icon: "◎", phase: "01" },
  { id: "dns",          label: "DNS",          icon: "⬢", phase: "02" },
  { id: "live",         label: "Live Hosts",   icon: "◉", phase: "03" },
  { id: "ports",        label: "Port Scan",    icon: "⬡", phase: "04" },
  { id: "urls",         label: "URLs",         icon: "◈", phase: "05" },
  { id: "screenshots",  label: "Screenshots",  icon: "▣", phase: "06" },
  { id: "confidential", label: "Confidential", icon: "⚿", phase: "07" },
  { id: "originip",     label: "Origin IP",    icon: "⊕", phase: "08" },
  { id: "intelligence", label: "Intelligence", icon: "◎", phase: "09" },
  { id: "nuclei",       label: "Nuclei",       icon: "⬡", phase: "10" },
];

export default function App() {
  const [page, setPage] = useState<Page>("targets");
  return (
    <div style={s.shell}>
      <aside style={s.sidebar}>
        <div style={s.brand}>
          <span style={s.brandBracket}>[</span>
          <span style={s.brandName}>RECON</span>
          <span style={s.brandBracket}>]</span>
        </div>
        <div style={s.brandSub}>Attack Surface Framework</div>
        <div style={s.divider} />
        <nav style={s.nav}>
          {NAV.map((item) => {
            const active = page === item.id;
            return (
              <button key={item.id} onClick={() => setPage(item.id)}
                style={{ ...s.navBtn, ...(active ? s.navBtnActive : {}) }}>
                {active && <span style={s.activeBar} />}
                <span style={{ ...s.navIcon, color: active ? "var(--cyan)" : "var(--text-muted)" }}>{item.icon}</span>
                <span style={s.navLabel}>{item.label}</span>
                {item.phase && (
                  <span style={{ ...s.navPhase, color: active ? "var(--cyan)" : "var(--text-muted)" }}>
                    PH-{item.phase}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
        <div style={{ flex: 1 }} />
        <div style={s.sidebarFooter}>
          <span style={s.footerDot} />
          <span style={s.footerText}>v1.0.0</span>
        </div>
      </aside>
      <main style={s.main}>
        <div key={page} className="animate-in" style={s.page}>
          {page === "targets"      && <TargetsPage />}
          {page === "subdomains"   && <SubdomainsPage />}
          {page === "dns"          && <DNSPage />}
          {page === "live"         && <LivePage />}
          {page === "ports"        && <PortsPage />}
          {page === "urls"         && <URLsPage />}
          {page === "screenshots"  && <ScreenshotsPage />}
          {page === "confidential" && <ConfidentialPage />}
          {page === "originip"     && <OriginIPPage />}
          {page === "intelligence" && <IntelligencePage />}
          {page === "nuclei"       && <NucleiPage />}
        </div>
      </main>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  shell: { display: "flex", height: "100vh", overflow: "hidden", background: "var(--bg-base)" },
  sidebar: {
    width: 220, flexShrink: 0, background: "var(--bg-panel)",
    borderRight: "1px solid var(--border)", display: "flex",
    flexDirection: "column", padding: "28px 0 18px",
  },
  brand: {
    display: "flex", justifyContent: "center", alignItems: "center", gap: 4,
    fontFamily: "var(--font-mono)", fontSize: 17, fontWeight: 700,
    letterSpacing: "0.08em", marginBottom: 4,
  },
  brandBracket: { color: "var(--cyan)" },
  brandName:    { color: "var(--text-primary)" },
  brandSub: {
    textAlign: "center" as const, fontFamily: "var(--font-mono)", fontSize: 9,
    color: "var(--text-muted)", letterSpacing: "0.18em",
    textTransform: "uppercase" as const, marginBottom: 24,
  },
  divider: { height: 1, background: "var(--border)", margin: "0 16px 20px" },
  nav: { display: "flex", flexDirection: "column" as const, gap: 2, padding: "0 8px" },
  navBtn: {
    position: "relative" as const, display: "flex", alignItems: "center", gap: 10,
    width: "100%", padding: "10px 14px", background: "transparent", border: "none",
    borderRadius: 6, cursor: "pointer", color: "var(--text-secondary)",
    fontFamily: "var(--font-ui)", fontSize: 13, fontWeight: 500,
    textAlign: "left" as const, transition: "background 0.15s, color 0.15s",
  },
  navBtnActive: { background: "var(--bg-hover)", color: "var(--text-primary)" },
  activeBar: {
    position: "absolute" as const, left: 0, top: "22%", bottom: "22%",
    width: 2, borderRadius: 1, background: "var(--cyan)",
  },
  navIcon: { fontSize: 13, width: 18, textAlign: "center" as const, flexShrink: 0 },
  navLabel: { flex: 1 },
  navPhase: { fontSize: 9, fontFamily: "var(--font-mono)", letterSpacing: "0.06em" },
  sidebarFooter: { display: "flex", alignItems: "center", gap: 8, padding: "0 20px", marginTop: 16 },
  footerDot: {
    display: "inline-block", width: 6, height: 6, borderRadius: "50%",
    background: "var(--green)", boxShadow: "0 0 6px var(--green)",
  },
  footerText: { fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" },
  main: { flex: 1, overflow: "auto" },
  page: { padding: "36px 44px", maxWidth: 1200 },
};
