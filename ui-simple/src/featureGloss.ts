const GLOSS: Record<string, string> = {
  duration: "seconds between the first and last packet seen on this flow",
  pkts_fwd: "packets sent by the side that opened the flow",
  pkts_rev: "packets sent back by the other side",
  bytes_fwd: "bytes sent by the side that opened the flow",
  bytes_rev: "bytes sent back by the other side, zero means nobody answered",
  bytes_per_pkt_fwd: "mean packet size in the forward direction",
  bytes_per_pkt_rev: "mean packet size on the reply direction",
  flags_seen_bitmap: "every tcp flag seen on this flow, folded into one number",
  completeness_flag: "1 when both directions of the flow were observed",
  directionality: "1 when both directions were seen, 0 when the tap saw only one",
  initiator_is_lo: "bookkeeping: which endpoint sorted first in the flow key, not a threat signal",
  orientation_confidence: "how sure we are which side opened the flow, 1 when a syn settled it",

  pps_to_dst: "packets per second arriving at this destination",
  pps_to_dst_ewma_dev: "packet rate to this destination, in sigmas above its own baseline",
  src_entropy_1s: "how spread out the source addresses are this second, 1 is maximally spread",
  src_entropy_ratio_1s: "source entropy against the packet count in the same second",
  src_cardinality_1s: "distinct sources hitting this destination in one second",
  src_cardinality_60s: "distinct sources hitting this destination over the last minute",
  src_cardinality_growth: "how much wider the minute is than the second, spoofed floods run wide",
  entropy_explosion_score: "sources suddenly fanned out, the spoofed-flood signature",
  entropy_collapse_score: "sources suddenly narrowed to a few, the reflection signature",
  syn_synack_ratio_1s: "half-open handshakes per completed one, over one second",
  amplification_ratio: "reply bytes for every request byte at this destination",
  mean_pkt_bytes_1s: "mean packet size arriving at this destination this second",
  half_open_60s: "handshakes opened at this destination but never closed, over a minute",
  teardown_ratio_60s: "share of connections that actually closed, low means exhaustion",
  concurrent_src_ports_60s: "distinct source address and port pairs at this destination this minute",

  iat_mean: "mean gap in seconds between check-ins on this channel",
  iat_std: "spread of those gaps",
  iat_cv: "variability of the gaps between check-ins, low means clockwork",
  iat_skew: "lopsidedness of the gap distribution",
  iat_kurtosis: "how heavy the tails of the gap distribution are",
  ls_peak_period_s: "the repeat interval the periodogram found, in seconds",
  ls_peak_power: "how strong that repeat is against the noise in the series",
  ls_fap: "chance a random flow would look this periodic, lower is stronger",
  dst_stability: "how consistently this source talks to one destination",
  beacon_sample_count: "how many gaps the periodicity test had to work with",
  beacon_span_s: "seconds of history behind the periodicity test",

  qname_char_entropy: "character randomness of the query name",
  qname_bigram_ll: "how normal the letter pairs look against a top-1M domain model",
  qname_len: "length of the query name",
  label_count: "number of dot-separated labels",
  max_label_len: "longest single label, 63 is the protocol maximum",
  digit_ratio: "fraction of the name that is digits",
  consonant_run_max: "longest run of consonants in the name",
  dga_entropy_component: "the entropy half of the name score, scaled 0 to 1",
  dga_bigram_component: "the letter-pair half of the name score, scaled 0 to 1",
  dga_name_score: "how machine-generated this one name looks, 0 to 1",
  dga_mean_name_score: "the same score averaged over every name this source asked for",
  nx_response_ratio: "share of this source's lookups that came back with no answer",
  distinct_regdom_300s: "distinct registered domains this source asked about in five minutes",
  source_query_count_300s: "dns queries this source made in five minutes",
  subdomain_cardinality: "distinct subdomains seen under one registered domain",
  subdomain_baseline: "what that subdomain count usually is for this source and zone",
  subdomain_excess: "how far the subdomain count sits above its own baseline",
  qtype_txt_null_ratio: "share of TXT and NULL queries, the records tunnels carry data in",
  qtype_txt_null_dev: "how far that TXT and NULL share sits above this source's own habit",

  fingerprint_consistency_score: "agreement between the TLS library and the OS the tcp header suggests",
  ja4_tcp_pair_share: "how often this TLS fingerprint pairs with this OS on this link",
  ja4_observation_count: "how many times this TLS fingerprint has been seen here",
  tls_version: "the TLS version the handshake settled on",
  tls_ext_count: "number of TLS extensions offered",
  tls_alpn_is_h2: "1 when the client offered http/2 first",
  splt_len: "how many packet size and timing samples this flow gave up",
  splt_mean_abs_len: "mean packet size across that size and timing sequence",
  splt_len_cv: "how varied those packet sizes are, machines are uniform",
  splt_iat_mean: "mean gap between packets in that sequence",
  splt_iat_cv: "how varied those gaps are",
  splt_up_down_ratio: "bytes out for every byte in across the sequence",
  splt_direction_changes: "how often the exchange changed direction, a real session changes often",
  ja4_reference_support_hosts: "how many hosts backed the expected pairing for this fingerprint",
  host_fingerprint_repeats: "consecutive handshakes from this source with the same tcp fingerprint",

  vertical_fanout: "distinct ports this source touched on one host",
  horizontal_fanout: "distinct hosts this source touched on one port",
  source_distinct_ports_3600s: "distinct ports this source touched anywhere in the last hour",
  source_distinct_hosts_3600s: "distinct hosts this source touched on any port in the last hour",
  strobe_score: "few ports across many hosts, the strobe pattern",
  rst_response_ratio: "share of probes answered with a reset",
  probe_completion_ratio: "share of probes that got a real handshake back",
  mean_bytes_per_probe: "mean size of the probe packets, probes are tiny",
  scan_probe_count_60s: "probes from this source in the last minute",

  out_in_byte_ratio: "outbound bytes for every inbound byte on this pair",
  out_in_ratio_ewma: "the same ratio against this pair's own running baseline",
  sustained_asymmetry_s: "seconds the outbound asymmetry has held",
  outbound_bytes_total: "total bytes this pair has sent outward",
  inbound_bytes_total: "total bytes that came back",
  peak_window_out_bytes: "largest outbound total in any single minute",
  upload_burst_score: "how much of the upload landed in one burst rather than a drip",
  dst_source_fanout_3600s: "distinct internal sources that reached this destination in the last hour",
  dst_novelty_score: "how new this destination is to the enclave, 1 is never seen before",
  peer_age_s: "seconds since this pair first appeared",
  reverse_direction_observed: "1 when the far side sent anything back at all",

  sampling_active: "1 when the ingest path was sampling rather than seeing every packet",
  sampling_ratio: "fraction of packets actually processed, 1.0 when nothing was dropped",
  shedding_tier: "0 for full processing, rising as stages are shed under load",

  src_cardinality_per_dst: "distinct sources hitting this destination",
  ja4_claims: "the client the TLS handshake claims to be",
  tcpfp_claims: "the operating system the TCP header suggests",
  splt_seq: "the packet size and timing sequence score from the sequence model",
  ext_count: "number of TLS extensions offered",
  mean_bytes_per_flow: "mean bytes per flow, probes are tiny",
  out_in_ratio_ewma_7d: "the same ratio against this pair's long baseline",
  sustained_asymmetry_duration: "seconds the asymmetry has held",
};

const WINDOW = /_(\d+)(s|m|h|d)$/;

// detector features carry their window in the name, so gloss the base and name the window
export function featureGloss(name: string): string {
  const exact = GLOSS[name];
  if (exact) return exact;
  const match = WINDOW.exec(name);
  if (!match) return "";
  const base = GLOSS[name.slice(0, match.index)];
  if (!base) return "";
  return `${base}, over ${windowWords(Number(match[1]), match[2])}`;
}

function windowWords(size: number, unit: string): string {
  const seconds = unit === "d" ? size * 86400 : unit === "h" ? size * 3600 : unit === "m" ? size * 60 : size;
  if (seconds === 1) return "one second";
  if (seconds === 60) return "the last minute";
  if (seconds === 300) return "the last five minutes";
  if (seconds === 3600) return "the last hour";
  if (seconds === 86400) return "the last day";
  if (seconds % 3600 === 0) return `the last ${seconds / 3600} hours`;
  if (seconds % 60 === 0) return `the last ${seconds / 60} minutes`;
  return `the last ${seconds} seconds`;
}
