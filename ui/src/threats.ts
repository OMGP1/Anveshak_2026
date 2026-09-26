import type { KeyboardEvent } from "react";

export type ThreatClass =
  | "benign"
  | "volumetric-ddos"
  | "c2-beaconing"
  | "dga-dns-tunnelling"
  | "encrypted-malware"
  | "recon-scanning"
  | "data-exfiltration"
  | "unknown-suspicious";

export type Theme = "light" | "dark";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ThreatInfo = {
  id: ThreatClass;
  letter: string;
  label: string;
  short: string;
  signal: string;
  technique: string;
  technique_name: string;
  light: string;
  dark: string;
};

// colours are categorical slots 1..6, validated for both surfaces
export const THREATS: ThreatInfo[] = [
  {
    id: "volumetric-ddos",
    letter: "a",
    label: "Volumetric DDoS",
    short: "DDoS",
    signal: "flow rate against a destination plus source-IP entropy",
    technique: "T1498.001",
    technique_name: "Direct Network Flood",
    light: "#2a78d6",
    dark: "#3987e5",
  },
  {
    id: "c2-beaconing",
    letter: "b",
    label: "C2 beaconing",
    short: "Beacon",
    signal: "periodicity of inter-arrival times toward a stable destination",
    technique: "T1071.001",
    technique_name: "Application Layer Protocol: Web Protocols",
    light: "#eb6834",
    dark: "#d95926",
  },
  {
    id: "dga-dns-tunnelling",
    letter: "c",
    label: "DGA and DNS tunnelling",
    short: "DGA/DNS",
    signal: "character entropy and bigram likelihood of query names",
    technique: "T1568.002",
    technique_name: "Dynamic Resolution: Domain Generation Algorithms",
    light: "#1baf7a",
    dark: "#199e70",
  },
  {
    id: "encrypted-malware",
    letter: "d",
    label: "Encrypted-session malware",
    short: "Encrypted",
    signal: "TLS metadata only: JA4, packet sizes and timing. no decryption",
    technique: "T1573",
    technique_name: "Encrypted Channel",
    light: "#eda100",
    dark: "#c98500",
  },
  {
    id: "recon-scanning",
    letter: "e",
    label: "Recon and port scanning",
    short: "Scan",
    signal: "fan-out from one source across many ports or hosts",
    technique: "T1046",
    technique_name: "Network Service Discovery",
    light: "#e87ba4",
    dark: "#d55181",
  },
  {
    id: "data-exfiltration",
    letter: "f",
    label: "Data exfiltration",
    short: "Exfil",
    signal: "asymmetric outbound-to-inbound byte ratio to a novel destination",
    technique: "T1048",
    technique_name: "Exfiltration Over Alternative Protocol",
    light: "#008300",
    dark: "#008300",
  },
  {
    id: "unknown-suspicious",
    letter: "?",
    label: "Unknown / unusual",
    short: "Unknown",
    signal: "rarity against an approved benign baseline; analyst review required",
    technique: "",
    technique_name: "No technique assigned",
    light: "#7c3aed",
    dark: "#a78bfa",
  },
];

const BENIGN: ThreatInfo = {
  id: "benign",
  letter: "-",
  label: "Benign",
  short: "Benign",
  signal: "nothing above threshold",
  technique: "",
  technique_name: "",
  light: "#64748b",
  dark: "#8b9bb4",
};

const BY_ID = new Map<string, ThreatInfo>([[BENIGN.id, BENIGN], ...THREATS.map((t) => [t.id, t] as const)]);

export function threat(id: string | null | undefined): ThreatInfo {
  return BY_ID.get(id ?? "benign") ?? BENIGN;
}

export function threatColour(id: string | null | undefined, theme: Theme): string {
  const info = threat(id);
  return theme === "dark" ? info.dark : info.light;
}

export function emptyCounts(): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const t of THREATS) counts[t.id] = 0;
  return counts;
}

export type ChartColours = {
  surface: string;
  grid: string;
  axis: string;
  text: string;
  series: string[];
  good: string;
  warn: string;
  danger: string;
  cool: string;
  coolText: string;
  neutral: string;
};

const LIGHT: ChartColours = {
  surface: "#ffffff",
  grid: "#dde3ec",
  axis: "#5b6b82",
  text: "#0f172a",
  series: ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"],
  good: "#16a34a",
  warn: "#d97706",
  danger: "#dc2626",
  cool: "#2a78d6",
  coolText: "#1d5fb0",
  neutral: "#94a3b8",
};

const DARK: ChartColours = {
  surface: "#0f1728",
  grid: "#223049",
  axis: "#8b9bb4",
  text: "#e5ecf6",
  series: ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300"],
  good: "#4ade80",
  warn: "#fbbf24",
  danger: "#f87171",
  cool: "#3987e5",
  coolText: "#3987e5",
  neutral: "#64748b",
};

export function chartColours(theme: Theme): ChartColours {
  return theme === "dark" ? DARK : LIGHT;
}

export function tooltipStyle(colours: ChartColours) {
  return { background: colours.surface, border: `1px solid ${colours.grid}`, borderRadius: 8, fontSize: 12 };
}

export function severityTone(severity: string): "ok" | "warn" | "danger" {
  if (severity === "CRITICAL" || severity === "HIGH") return "danger";
  if (severity === "MEDIUM") return "warn";
  return "ok";
}

// capture timestamps are utc; slicing avoids shifting them into local time
export function formatTime(iso: string): string {
  return iso.slice(11, 19);
}

export function formatDateTime(iso: string): string {
  return iso.slice(0, 10) + " " + iso.slice(11, 19);
}

export function formatClock(ts: number | null | undefined): string {
  if (ts == null) return "--:--:--";
  return new Date(ts * 1000).toISOString().slice(11, 19);
}

export function percent(value: number | null | undefined, digits = 0): string {
  return value == null ? "n/a" : (value * 100).toFixed(digits) + "%";
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatMB(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatCount(n: number): string {
  if (n < 1000) return String(Math.round(n));
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(2)}M`;
}

export function formatRate(n: number): string {
  if (n >= 1000) return formatCount(n);
  if (n >= 100) return n.toFixed(0);
  if (n >= 10) return n.toFixed(1);
  return n.toFixed(2);
}

export function formatMs(ms: number | null | undefined): string {
  if (ms == null) return "n/a";
  if (ms < 1) return `${(ms * 1000).toFixed(0)} us`;
  if (ms < 100) return `${ms.toFixed(2)} ms`;
  return `${ms.toFixed(0)} ms`;
}

// "5 s", "2 min 30 s", "1 h 5 min"
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m} min ${s % 60} s` : `${m} min`;
  const h = Math.floor(m / 60);
  return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
}

// lets a clickable row respond to Enter and Space like a button
export function activateOnEnter(action: () => void) {
  return (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      action();
    }
  };
}
