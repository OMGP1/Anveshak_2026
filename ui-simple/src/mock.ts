import {
  IDLE_STATUS,
  type Alert,
  type Coverage,
  type EngineClient,
  type EvidenceItem,
  type LedgerVerdict,
  type MetricsSnapshot,
  type ReplayStatus,
  type Scenario,
  type StreamEvent,
  type StreamHandlers,
} from "./api";
import type { Severity, ThreatClass } from "./threats";
import { threat } from "./threats";

const TICK_MS = 500;

const SCENARIOS: Scenario[] = [
  {
    id: "benign-baseline",
    name: "Benign baseline",
    file: "data/scenarios/01_benign_baseline.pcap",
    proves: "false-positive rate and steady-state memory",
    threat_class: "benign",
    packets: 2_140_000,
    duration_s: 300,
  },
  {
    id: "syn-flood",
    name: "SYN flood, spoofed sources",
    file: "data/scenarios/02_syn_flood.pcap",
    proves: "source-entropy explosion under a spoofed flood",
    threat_class: "volumetric-ddos",
    packets: 4_820_000,
    duration_s: 120,
  },
  {
    id: "udp-reflection",
    name: "UDP/DNS reflection",
    file: "data/scenarios/03_udp_reflection.pcap",
    proves: "entropy collapse, the other DDoS sub-type",
    threat_class: "volumetric-ddos",
    packets: 3_110_000,
    duration_s: 120,
  },
  {
    id: "slowloris",
    name: "Slowloris exhaustion",
    file: "data/scenarios/04_slowloris.pcap",
    proves: "low-rate protocol exhaustion, no volume signal",
    threat_class: "volumetric-ddos",
    packets: 96_000,
    duration_s: 240,
  },
  {
    id: "c2-beacon-jitter",
    name: "Jittered C2 beacon, plus or minus 30 percent",
    file: "data/scenarios/05_beacon_jitter.pcap",
    proves: "Lomb-Scargle finds a period an FFT misses",
    threat_class: "c2-beaconing",
    packets: 41_000,
    duration_s: 900,
  },
  {
    id: "dga-burst",
    name: "DGA burst, high-entropy and dictionary",
    file: "data/scenarios/06_dga_burst.pcap",
    proves: "bigram likelihood catches what entropy alone misses",
    threat_class: "dga-dns-tunnelling",
    packets: 128_000,
    duration_s: 180,
  },
  {
    id: "dns-tunnel",
    name: "DNS tunnelling, iodine",
    file: "data/scenarios/07_dns_tunnel.pcap",
    proves: "subdomain cardinality survives base32 encoding",
    threat_class: "dga-dns-tunnelling",
    packets: 310_000,
    duration_s: 300,
  },
  {
    id: "ja4-spoof",
    name: "JA4-spoofed TLS from a Linux host",
    file: "data/scenarios/08_ja4_spoof.pcap",
    proves: "cross-layer disagreement between JA4 and the TCP fingerprint",
    threat_class: "encrypted-malware",
    packets: 74_000,
    duration_s: 240,
  },
  {
    id: "port-scan",
    name: "nmap fast scan plus a slow scan",
    file: "data/scenarios/09_port_scan.pcap",
    proves: "multi-scale windows catch both scan speeds",
    threat_class: "recon-scanning",
    packets: 512_000,
    duration_s: 360,
  },
  {
    id: "slow-exfil",
    name: "Slow-drip exfiltration",
    file: "data/scenarios/10_slow_exfil.pcap",
    proves: "long-window EWMA beats a single-window threshold",
    threat_class: "data-exfiltration",
    packets: 205_000,
    duration_s: 600,
  },
];

const CAPS: Record<string, number> = {
  flow_table: 200_000 * 160,
  beacon_table: 50_000 * 608,
  sketches: 20_000_000,
  models: 33_554_432,
};

type EvidenceTemplate = { name: string; subtype: string; summary: string; evidence: EvidenceItem[] };

const TEMPLATES: Record<ThreatClass, EvidenceTemplate[]> = {
  "unknown-suspicious": [],
  benign: [],
  "volumetric-ddos": [
    {
      name: "Suspected spoofed-source SYN flood",
      subtype: "syn-flood",
      summary: "SYN:SYN-ACK ratio 41:1 with near-maximal source-IP entropy over 1 s",
      evidence: [
        { feature: "syn_synack_ratio_1s", value: 41.2, shap: 0.34 },
        { feature: "src_entropy_1s", value: 0.97, shap: 0.21 },
        { feature: "pps_to_dst_ewma_dev", value: 8.4, shap: 0.18 },
        { feature: "completeness_flag", value: 0, shap: 0.09 },
        { feature: "bytes_per_pkt_fwd", value: 60, shap: -0.04 },
      ],
    },
    {
      name: "Suspected UDP reflection and amplification",
      subtype: "reflection-amplification",
      summary: "Source entropy collapsed while reply bytes ran 54x request bytes",
      evidence: [
        { feature: "entropy_collapse_score", value: 0.88, shap: 0.31 },
        { feature: "amplification_ratio", value: 54.1, shap: 0.27 },
        { feature: "pps_to_dst_ewma_dev", value: 6.9, shap: 0.16 },
        { feature: "src_cardinality_per_dst", value: 12, shap: 0.07 },
        { feature: "duration", value: 0.4, shap: -0.03 },
      ],
    },
  ],
  "c2-beaconing": [
    {
      name: "Suspected C2 beacon with jitter",
      subtype: "jittered-beacon",
      summary: "Inter-arrivals repeat every 61 s with a false-alarm probability of 4e-6",
      evidence: [
        { feature: "ls_fap", value: 4e-6, shap: 0.36 },
        { feature: "ls_peak_period_s", value: 61.2, shap: 0.22 },
        { feature: "iat_cv", value: 0.29, shap: 0.19 },
        { feature: "dst_stability", value: 0.94, shap: 0.11 },
        { feature: "bytes_per_pkt_fwd", value: 212, shap: -0.05 },
      ],
    },
  ],
  "dga-dns-tunnelling": [
    {
      name: "Suspected DGA query burst",
      subtype: "dga-high-entropy",
      summary: "Query names score far below the Tranco bigram model at high character entropy",
      evidence: [
        { feature: "qname_bigram_ll", value: -9.8, shap: 0.33 },
        { feature: "qname_char_entropy", value: 3.91, shap: 0.24 },
        { feature: "consonant_run_max", value: 7, shap: 0.12 },
        { feature: "digit_ratio", value: 0.28, shap: 0.08 },
        { feature: "qname_len", value: 24, shap: -0.03 },
      ],
    },
    {
      name: "Suspected DNS tunnelling",
      subtype: "dns-tunnel",
      summary: "Subdomain cardinality 3.1k under one registered domain, mostly TXT queries",
      evidence: [
        { feature: "subdomain_cardinality", value: 3104, shap: 0.35 },
        { feature: "qtype_txt_null_ratio", value: 0.86, shap: 0.26 },
        { feature: "max_label_len", value: 63, shap: 0.14 },
        { feature: "qname_char_entropy", value: 4.42, shap: 0.09 },
        { feature: "label_count", value: 5, shap: -0.02 },
      ],
    },
  ],
  "encrypted-malware": [
    {
      name: "TLS fingerprint contradicts the OS fingerprint",
      subtype: "ja4-tcp-mismatch",
      summary: "JA4 claims Chrome on Windows, the TCP fingerprint is a Linux kernel",
      evidence: [
        { feature: "fingerprint_consistency_score", value: 0.04, shap: 0.38 },
        { feature: "ja4_claims", value: 1, shap: 0.19 },
        { feature: "tcpfp_claims", value: 0, shap: 0.17 },
        { feature: "splt_seq", value: 0.71, shap: 0.12 },
        { feature: "ext_count", value: 14, shap: -0.04 },
      ],
    },
  ],
  "recon-scanning": [
    {
      name: "Vertical port scan",
      subtype: "vertical-scan",
      summary: "One source touched 1.8k distinct ports on one host with tiny flows",
      evidence: [
        { feature: "vertical_fanout", value: 1834, shap: 0.37 },
        { feature: "rst_response_ratio", value: 0.91, shap: 0.21 },
        { feature: "mean_bytes_per_flow", value: 64, shap: 0.15 },
        { feature: "horizontal_fanout", value: 3, shap: -0.06 },
        { feature: "duration", value: 0.02, shap: 0.04 },
      ],
    },
    {
      name: "Slow horizontal sweep",
      subtype: "slow-scan",
      summary: "One port probed across 940 hosts over an hour, invisible to a 1 s window",
      evidence: [
        { feature: "horizontal_fanout", value: 940, shap: 0.34 },
        { feature: "strobe_score", value: 0.88, shap: 0.22 },
        { feature: "mean_bytes_per_flow", value: 60, shap: 0.13 },
        { feature: "rst_response_ratio", value: 0.76, shap: 0.1 },
        { feature: "vertical_fanout", value: 1, shap: -0.07 },
      ],
    },
  ],
  "data-exfiltration": [
    {
      name: "Sustained outbound asymmetry to a new destination",
      subtype: "slow-drip-exfil",
      summary: "Outbound bytes ran 96x inbound for 14 minutes to a first-seen destination",
      evidence: [
        { feature: "out_in_byte_ratio", value: 96.4, shap: 0.33 },
        { feature: "sustained_asymmetry_duration", value: 842, shap: 0.24 },
        { feature: "dst_novelty_score", value: 0.97, shap: 0.18 },
        { feature: "out_in_ratio_ewma_7d", value: 11.2, shap: 0.08 },
        { feature: "upload_burst_score", value: 0.21, shap: -0.05 },
      ],
    },
  ],
};

const COVERAGE: Coverage = {
  high_confidence: 0.62,
  low_confidence: 0.27,
  unclassifiable_opaque: 0.11,
  reasons: [
    {
      code: "payload-opaque",
      label: "Payload is never read",
      fraction: 0.11,
      detail: "Constraint C-b discards payload at the parse boundary, so content-based classes are out of reach.",
    },
    {
      code: "ech-hidden-sni",
      label: "SNI hidden by Encrypted Client Hello",
      fraction: 0.06,
      detail: "With ECH the server name is encrypted, so only JA4 and packet timing remain.",
    },
    {
      code: "quic-handshake",
      label: "QUIC obscures handshake metadata",
      fraction: 0.05,
      detail: "QUIC encrypts most of its handshake, leaving fewer fields than TLS over TCP.",
    },
  ],
};

function pick<T>(items: T[]): T {
  return items[Math.floor(Math.random() * items.length)];
}

function jitter(value: number, spread: number): number {
  return value * (1 + (Math.random() - 0.5) * spread);
}

function hex(n: number): string {
  let out = "";
  for (let i = 0; i < n; i++) out += "0123456789abcdef"[Math.floor(Math.random() * 16)];
  return out;
}

function uuid(): string {
  return `${hex(8)}-${hex(4)}-4${hex(3)}-a${hex(3)}-${hex(12)}`;
}

function ip(): string {
  return `10.${Math.floor(Math.random() * 40)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
}

function severityFor(confidence: number): Severity {
  if (confidence >= 92) return "CRITICAL";
  if (confidence >= 78) return "HIGH";
  if (confidence >= 60) return "MEDIUM";
  return "LOW";
}

class MockEngine {
  private listeners = new Set<(event: StreamEvent) => void>();
  private status: ReplayStatus = { ...IDLE_STATUS };
  private scenario: Scenario = SCENARIOS[1];
  private alerts: Alert[] = [];
  private timer: number | undefined;
  private startedAt = 0;
  private captureStart = Date.parse("2026-09-07T10:00:00Z") / 1000;
  private elapsed = 0;
  private nextAlertIn = 3;
  private packets = 0;
  private flows = 0;
  private dropped = 0;
  private prevHash = hex(64);
  private lastMetrics: MetricsSnapshot = this.snapshot(0, 0, 0);

  subscribe(listener: (event: StreamEvent) => void): () => void {
    this.listeners.add(listener);
    listener({ type: "status", payload: this.status });
    return () => this.listeners.delete(listener);
  }

  private emit(event: StreamEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  getStatus(): ReplayStatus {
    return this.status;
  }

  getMetrics(): MetricsSnapshot {
    return this.lastMetrics;
  }

  getAlerts(limit = 200): Alert[] {
    return this.alerts.slice(0, limit);
  }

  findAlert(id: string): Alert | undefined {
    return this.alerts.find((a) => a.id === id);
  }

  ledger(): LedgerVerdict {
    return {
      ok: true,
      records: this.alerts.length,
      broken_at: null,
      anchors_ok: true,
      head: "sha256:" + this.prevHash,
    };
  }

  start(id: string, speed: number, mode: "virtual" | "realtime"): ReplayStatus {
    this.scenario = SCENARIOS.find((s) => s.id === id) ?? SCENARIOS[0];
    this.alerts = [];
    this.elapsed = 0;
    this.packets = 0;
    this.flows = 0;
    this.dropped = 0;
    this.nextAlertIn = 3;
    this.startedAt = Date.now();
    this.status = {
      running: true,
      paused: false,
      scenario: this.scenario.id,
      speed,
      mode,
      clock_ts: this.captureStart,
      progress: 0,
      alerts: 0,
    };
    window.clearInterval(this.timer);
    this.timer = window.setInterval(() => this.tick(), TICK_MS);
    this.emit({ type: "status", payload: this.status });
    return this.status;
  }

  pause(): ReplayStatus {
    if (this.status.running) this.status = { ...this.status, paused: true };
    this.emit({ type: "status", payload: this.status });
    return this.status;
  }

  resume(): ReplayStatus {
    if (this.status.running) this.status = { ...this.status, paused: false };
    this.emit({ type: "status", payload: this.status });
    return this.status;
  }

  stop(): ReplayStatus {
    window.clearInterval(this.timer);
    this.timer = undefined;
    this.status = { ...this.status, running: false, paused: false };
    this.emit({ type: "status", payload: this.status });
    return this.status;
  }

  private rates(): { pps: number; fps: number; mbps: number } {
    const base = this.scenario.packets / this.scenario.duration_s;
    const pps = this.status.mode === "virtual" ? jitter(base * 9.2, 0.06) : jitter(base * this.status.speed, 0.08);
    const perFlow = this.scenario.threat_class === "volumetric-ddos" ? 2.4 : 11;
    const meanBytes = this.scenario.threat_class === "volumetric-ddos" ? 74 : 640;
    return { pps, fps: pps / perFlow, mbps: (pps * meanBytes * 8) / 1e6 };
  }

  private tick(): void {
    if (!this.status.running || this.status.paused) return;
    const step = (TICK_MS / 1000) * (this.status.mode === "virtual" ? this.status.speed * 9.2 : this.status.speed);
    this.elapsed = Math.min(this.scenario.duration_s, this.elapsed + step);
    const { pps, fps, mbps } = this.rates();
    this.packets += pps * (TICK_MS / 1000);
    this.flows += fps * (TICK_MS / 1000);

    const done = this.elapsed >= this.scenario.duration_s;
    this.status = {
      ...this.status,
      running: !done,
      clock_ts: this.captureStart + this.elapsed,
      progress: this.elapsed / this.scenario.duration_s,
      alerts: this.alerts.length,
    };
    if (done) window.clearInterval(this.timer);

    this.nextAlertIn -= TICK_MS / 1000;
    if (this.nextAlertIn <= 0) {
      this.nextAlertIn = 1.5 + Math.random() * 4;
      const alert = this.buildAlert();
      if (alert) {
        this.alerts = [alert, ...this.alerts].slice(0, 400);
        this.status = { ...this.status, alerts: this.alerts.length };
        this.emit({ type: "alert", payload: alert });
      }
    }

    this.lastMetrics = this.snapshot(pps, fps, mbps);
    this.emit({ type: "metrics", payload: this.lastMetrics });
    this.emit({ type: "status", payload: this.status });
  }

  private snapshot(pps: number, fps: number, mbps: number): MetricsSnapshot {
    const load = this.status.mode === "virtual" ? 1 : Math.min(1, this.status.speed / 12);
    const depth = Math.round(jitter(120 + load * 900, 0.3));
    if (depth > 900) this.dropped += Math.round(Math.random() * 4);
    const p50 = jitter(1.4 + load * 1.1, 0.15);
    const flowEntries = Math.min(200_000, Math.round(this.flows * 0.06) + 4200);
    return {
      uptime_s: this.startedAt ? (Date.now() - this.startedAt) / 1000 : 0,
      packets: Math.round(this.packets),
      flows: Math.round(this.flows),
      alerts: this.alerts.length,
      packets_per_s: pps,
      flows_per_s: fps,
      mbps,
      latency_ms: { p50, p95: p50 * 2.8, p99: p50 * 4.6, p999: p50 * 9.1 },
      latency_histogram: [0.5, 1, 2, 4, 8, 16, 32, 64].map((le, i) => ({
        le_ms: le,
        count: Math.round(6000 * Math.exp(-Math.pow(i - 2.2, 2) / 2.6)),
      })),
      rss_mb: jitter(148, 0.02),
      flow_table_entries: flowEntries,
      memory_bytes: {
        flow_table: flowEntries * 160,
        beacon_table: Math.min(50_000, Math.round(this.flows * 0.004) + 900) * 608,
        sketches: 19_512_000,
        models: 31_457_280,
      },
      memory_caps_bytes: CAPS,
      stage_timing_us: {
        decode: jitter(1.9, 0.12),
        flow_table: jitter(0.8, 0.12),
        features: jitter(2.6, 0.12),
        tier1: jitter(3.4, 0.12),
        tier2: jitter(0.9, 0.3),
        alert: jitter(0.5, 0.2),
      },
      queue: {
        depth,
        capacity: 1024,
        dropped: this.dropped,
        shedding_tier: depth > 900 ? "sample" : depth > 600 ? "drop-l7" : "none",
      },
    };
  }

  private buildAlert(): Alert | null {
    const templates = TEMPLATES[this.scenario.threat_class];
    if (templates.length === 0) return null;
    const template = pick(templates);
    const info = threat(this.scenario.threat_class);
    const confidence = Math.round(58 + Math.random() * 40);
    const at = new Date((this.captureStart + this.elapsed) * 1000).toISOString();
    const dstPort = pick([53, 80, 443, 8443, 22]);
    const flow = {
      proto: this.scenario.threat_class === "dga-dns-tunnelling" ? "UDP" : "TCP",
      src_ip: ip(),
      dst_ip: ip(),
      src_port: 1024 + Math.floor(Math.random() * 60000),
      dst_port: dstPort,
      directionality: this.scenario.threat_class === "volumetric-ddos" ? "FWD_ONLY" : "BIDIRECTIONAL",
      completeness_flag: this.scenario.threat_class !== "volumetric-ddos",
      window_start: at,
      window_end: at,
    };
    this.prevHash = hex(64);
    return {
      type: "indicator",
      spec_version: "2.1",
      id: `indicator--${uuid()}`,
      created: at,
      name: template.name,
      description: `${template.summary}, against ${flow.dst_ip}:${flow.dst_port}.`,
      indicator_types: ["anomalous-activity"],
      pattern: `[network-traffic:dst_ref.value = '${flow.dst_ip}' AND network-traffic:dst_port = ${flow.dst_port}]`,
      pattern_type: "stix",
      valid_from: at,
      confidence,
      x_flow_identifier: flow,
      x_threat_class: this.scenario.threat_class,
      x_subtype: template.subtype,
      x_severity: severityFor(confidence),
      x_confidence_calibrated: true,
      x_detector: "tier1-lgbm + rule",
      x_latency_ms: Number(jitter(2.4, 0.5).toFixed(2)),
      x_model_lineage: {
        model_id: "tier1-lgbm-v1.2.0",
        model_hash: "sha256:" + hex(16),
        dataset_version: "2026-09-01-synthetic-v3",
      },
      x_supporting_evidence: template.evidence.map((e) => ({ ...e, value: Number(jitter(e.value, 0.1).toFixed(3)) })),
      x_detection_context: { sampling_active: false, sampling_ratio: 1, shedding_tier: "none" },
      x_prev_hash: "sha256:" + this.prevHash,
      external_references: [
        { source_name: "mitre-attack", external_id: info.technique, description: info.technique_name },
      ],
      labels: ["cii-relevant"],
    };
  }
}

const engine = new MockEngine();

function delay<T>(value: T): Promise<T> {
  return new Promise((resolve) => window.setTimeout(() => resolve(value), 60));
}

export const mockClient: EngineClient = {
  scenarios: () => delay(SCENARIOS),
  status: () => delay(engine.getStatus()),
  start: (request) => delay(engine.start(request.scenario, request.speed, request.mode)),
  pause: () => delay(engine.pause()),
  resume: () => delay(engine.resume()),
  stop: () => delay(engine.stop()),
  alerts: (options) => delay(engine.getAlerts(options?.limit ?? 200)),
  alert: (id) => {
    const found = engine.findAlert(id);
    return found ? delay(found) : Promise.reject(new Error("no such alert"));
  },
  metrics: () => delay(engine.getMetrics()),
  coverage: () => delay(COVERAGE),
  verifyLedger: () => delay(engine.ledger()),
  connect: (handlers: StreamHandlers) => {
    handlers.onOpen?.();
    const off = engine.subscribe(handlers.onEvent);
    return () => {
      off();
      handlers.onClose?.();
    };
  },
};
