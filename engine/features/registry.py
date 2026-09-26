from __future__ import annotations

from typing import Any

GROUPS = [
    "flow-structural",
    "ddos",
    "beaconing",
    "dga-dns",
    "encrypted",
    "scan",
    "exfil",
    "context",
]

FEATURES: list[dict[str, Any]] = [
    {
        "name": "duration",
        "group": "flow-structural",
        "dtype": "float",
        "definition": "seconds between the first and last packet observed for this flow key",
        "rationale": "separates a completed session from a probe and bounds every rate this flow "
                     "contributes to",
        "threat_class": "all",
    },
    {
        "name": "pkts_fwd",
        "group": "flow-structural",
        "dtype": "int",
        "definition": "packets sent by the flow initiator, after the orientation bit has been resolved",
        "rationale": "forward and reverse counts are only meaningful once the initiator is known, "
                     "which is why orientation is resolved before any counter is read",
        "threat_class": "all",
    },
    {
        "name": "pkts_rev",
        "group": "flow-structural",
        "dtype": "int",
        "definition": "packets sent by the flow responder, that is back toward the initiator",
        "rationale": "a zero here on a tcp flow means the far side never answered, which is the "
                     "shape of a scan probe and of a spoofed-source flood",
        "threat_class": "all",
    },
    {
        "name": "bytes_fwd",
        "group": "flow-structural",
        "dtype": "int",
        "definition": "ip total-length bytes sent by the initiator",
        "rationale": "the numerator of every asymmetry ratio in the exfiltration detector",
        "threat_class": "all",
    },
    {
        "name": "bytes_rev",
        "group": "flow-structural",
        "dtype": "int",
        "definition": "ip total-length bytes sent by the responder",
        "rationale": "the denominator of every asymmetry ratio, and zero means the ratio is a lower "
                     "bound rather than a measurement",
        "threat_class": "all",
    },
    {
        "name": "bytes_per_pkt_fwd",
        "group": "flow-structural",
        "dtype": "float",
        "definition": "bytes_fwd divided by pkts_fwd, the mean forward packet size",
        "rationale": "probes and keepalives are tiny, bulk transfer is near the mtu, and the two do "
                     "not overlap",
        "threat_class": "all",
    },
    {
        "name": "bytes_per_pkt_rev",
        "group": "flow-structural",
        "dtype": "float",
        "definition": "bytes_rev divided by pkts_rev, the mean reverse packet size",
        "rationale": "large reverse packets against tiny forward packets is the amplification shape",
        "threat_class": "all",
    },
    {
        "name": "flags_seen_bitmap",
        "group": "flow-structural",
        "dtype": "int",
        "definition": "bitwise or of every tcp flag byte observed on the flow",
        "rationale": "a flow that never carried fin or rst never closed, which is what connection "
                     "exhaustion looks like from outside",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "completeness_flag",
        "group": "flow-structural",
        "dtype": "bool",
        "definition": "true when packets were observed in both directions",
        "rationale": "on a one-way tap this is the honest marker of whether a ratio was measured or "
                     "assumed, and it is carried into the alert",
        "threat_class": "all",
    },
    {
        "name": "directionality",
        "group": "flow-structural",
        "dtype": "bool",
        "definition": "1 when both directions were seen, 0 when only one was",
        "rationale": "the numeric form of completeness_flag for the model layer",
        "threat_class": "all",
    },
    {
        "name": "initiator_is_lo",
        "group": "context",
        "dtype": "bool",
        "definition": "1 when the initiator is the lexicographically lower endpoint of the flow key",
        "rationale": "bookkeeping for the key normalisation, not a threat signal. kept out of the model "
                     "because address ordering correlates with the fixed attacker ranges of a synthetic "
                     "corpus, which is leakage rather than detection",
        "threat_class": "all",
    },
    {
        "name": "orientation_confidence",
        "group": "flow-structural",
        "dtype": "float",
        "definition": "1.0 when a syn or syn-ack fixed the initiator, 0.5 when it was inferred from "
                      "the first packet seen, 0.0 when unknown",
        "rationale": "a mid-flow pickup can be oriented backwards, and every downstream ratio "
                     "inherits that doubt, so it is reported rather than hidden",
        "threat_class": "all",
    },
    {
        "name": "pps_to_dst",
        "group": "ddos",
        "dtype": "float",
        "definition": "packets per second arriving at one destination address, measured over the "
                      "one-second bucket that just closed",
        "rationale": "the raw rate. it is reported next to the deviation so a reader can see whether "
                     "a large sigma came from a large rate or from a very quiet baseline",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "pps_to_dst_ewma_dev",
        "group": "ddos",
        "dtype": "float",
        "definition": "(pps - baseline mean) divided by sqrt(max(baseline variance, baseline mean, "
                      "1)). the baseline is a per-destination ewma with alpha 0.1 whose update is "
                      "clipped at 4 sigma, and it falls back to the enclave-wide per-destination "
                      "rate prior until the destination has 5 observations of its own",
        "rationale": "three deliberate choices. the poisson floor stops a perfectly steady baseline "
                     "producing a zero or infinite z-score. the clipped update stops an attack "
                     "training the detector to accept itself. the population fallback lets a "
                     "first-seen destination be judged at all, and the alert says which baseline "
                     "was used",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "src_entropy_1s",
        "group": "ddos",
        "dtype": "float",
        "definition": "shannon entropy of source addresses reaching this destination in a one-second "
                      "sliding window, normalised by log of the distinct count, so 0..1",
        "rationale": "the problem statement names source-ip entropy directly. normalised entropy "
                     "saturates near 1.0 for both 35 and 140 uniform sources, which is exactly why "
                     "it is not used alone",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "src_entropy_ratio_1s",
        "group": "ddos",
        "dtype": "float",
        "definition": "entropy in bits divided by log2 of the smaller of the packet count and the "
                      "512 slots the sliding counter holds, so the ceiling is the entropy actually "
                      "reachable rather than the one a bigger flood would need",
        "rationale": "the fraction of the reachable entropy the window carries. it approaches 1 when "
                     "nearly every packet brings a fresh source, which is the spoofed-flood "
                     "signature, and it stays there as the flood gets faster instead of decaying",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "src_cardinality_1s",
        "group": "ddos",
        "dtype": "float",
        "definition": "distinct source addresses to this destination in one second, counted in a "
                      "512-slot sliding table allocated only for destinations above 8 packets/s",
        "rationale": "lazy allocation keeps the per-destination entropy state off the 99 percent of "
                     "destinations that never carry a flood",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "src_cardinality_60s",
        "group": "ddos",
        "dtype": "float",
        "definition": "distinct source addresses to this destination over a rotating 60 second "
                      "hyperloglog, so the window covers between 60 and 120 seconds",
        "rationale": "the wide-window count is what reveals whether the source set is growing or has "
                     "saturated",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "src_cardinality_growth",
        "group": "ddos",
        "dtype": "float",
        "definition": "src_cardinality_60s divided by src_cardinality_1s",
        "rationale": "the discriminant between the two sub-types, and the strongest one available. a "
                     "spoofed flood draws from an effectively unbounded address space so the ratio "
                     "grows with the window (measured 21 on the syn flood scenario). reflection "
                     "draws from a finite reflector list so it saturates (measured 1.4). fifteen "
                     "times apart, and it is a physical difference, not a tuned threshold",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "entropy_explosion_score",
        "group": "ddos",
        "dtype": "float",
        "definition": "clamped (src_entropy_ratio_1s - 0.55) / 0.35 multiplied by clamped "
                      "(src_cardinality_growth - 2) / 6, zero when no entropy state exists",
        "rationale": "the spoofed-source flood score. both factors must hold: the window must be "
                     "near-maximally diverse and the diversity must keep growing. measured 1.00 on "
                     "the syn flood scenario and 0.00 on the reflection scenario",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "entropy_collapse_score",
        "group": "ddos",
        "dtype": "float",
        "definition": "clamped (3 - src_cardinality_growth) / 2 multiplied by clamped "
                      "(mean_pkt_bytes_1s - 120) / 280, forced to zero below 3 distinct sources",
        "rationale": "the reflection and amplification score. a saturated source set carrying large "
                     "replies. measured 0.76 to 0.99 on the reflection scenario and 0.00 on the syn "
                     "flood. the two sub-types call for opposite responses, so they are never "
                     "collapsed into one number",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "syn_synack_ratio_1s",
        "group": "ddos",
        "dtype": "float",
        "definition": "syns arriving at this destination divided by syn-acks leaving it, per second, "
                      "floored at one syn-ack",
        "rationale": "orientation matters here. syns are counted toward the destination and syn-acks "
                     "away from it, because on a spoofed flood the syn-acks are addressed to the "
                     "forged sources and never come back to the same key",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "udp_packet_share",
        "group": "ddos", "dtype": "float", "model_input": False,
        "definition": "Fraction of packets in the completed destination bucket whose transport is UDP.",
        "rationale": "Prevents TCP transfers from satisfying a UDP reflection rule; retained as rule evidence, "
                     "excluded from the existing trained feature contract.",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "reflection_service_share",
        "group": "ddos", "dtype": "float", "model_input": False,
        "definition": "Fraction of UDP packets arriving from a configured possible reflection service port.",
        "rationale": "Adds transport and service context to inbound byte asymmetry; a port alone does not "
                     "prove reflection. Excluded from the existing trained feature contract.",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "udp_egress_observed",
        "group": "ddos", "dtype": "bool", "model_input": False,
        "definition": "One when any outbound UDP bytes were observed for this destination in the rate window.",
        "rationale": "Makes a missing denominator visible instead of claiming a measured request/reply "
                     "amplification factor. Excluded from the existing trained feature contract.",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "amplification_ratio",
        "group": "ddos",
        "dtype": "float",
        "definition": "observed UDP bytes arriving at this destination divided by max(1, observed UDP "
                      "bytes sent), over a 60 second tumbling window",
        "rationale": "UDP byte asymmetry is supporting evidence, not a matched request/reply factor; "
                     "a missing return path can inflate it. TCP bytes are excluded.",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "mean_pkt_bytes_1s",
        "group": "ddos",
        "dtype": "float",
        "definition": "mean ip total length of packets to this destination in the last second",
        "rationale": "44 bytes is a bare syn, 508 is a dns any reply. the packet size alone splits "
                     "the flood sub-types before any entropy is computed",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "half_open_60s",
        "group": "ddos",
        "dtype": "float",
        "definition": "syns to this destination minus fins and rsts seen for it, over a 60 second "
                      "tumbling window, floored at zero",
        "rationale": "a proxy for concurrent connections held open. it is the only rate-independent "
                     "ddos signal here, which is what makes slowloris visible at 19 packets/s",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "teardown_ratio_60s",
        "group": "ddos",
        "dtype": "float",
        "definition": "fins plus rsts divided by syns for this destination over the same window",
        "rationale": "healthy traffic closes what it opens. a ratio near zero with hundreds of syns "
                     "means the connections are being held deliberately",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "concurrent_src_ports_60s",
        "group": "ddos",
        "dtype": "float",
        "definition": "distinct (source address, source port) pairs seen for this destination over a "
                      "rotating 60 second hyperloglog",
        "rationale": "the closest passive estimate of how many sockets a destination is being asked "
                     "to hold, which is the resource connection exhaustion actually consumes",
        "threat_class": "volumetric-ddos",
    },
    {
        "name": "iat_mean",
        "group": "beaconing",
        "dtype": "float",
        "definition": "mean gap in seconds between consecutive session starts on one (client, "
                      "server, port) channel, over the 64-sample ring",
        "rationale": "the naive period estimate. it is reported so a reader can see when the "
                     "periodogram and the mean disagree, which happens when beats are dropped",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "iat_std",
        "group": "beaconing",
        "dtype": "float",
        "definition": "population standard deviation of those gaps, welford online",
        "rationale": "the jitter budget in absolute seconds, which is what an analyst needs to "
                     "decide whether a schedule is tight or loose",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "iat_cv",
        "group": "beaconing",
        "dtype": "float",
        "definition": "iat_std divided by iat_mean, the scale-free measure of schedule jitter",
        "rationale": "the fallback statistic. when an implant sleeps for period times a random "
                     "factor the phase becomes a random walk and no periodogram can hold coherence, "
                     "but the coefficient of variation still separates a scheduled channel from "
                     "human traffic. measured 0.17 on the 30 percent jittered beacon",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "iat_skew",
        "group": "beaconing",
        "dtype": "float",
        "definition": "third standardised moment of the gap series, welford online",
        "rationale": "a long right tail means missed check-ins rather than a different period",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "iat_kurtosis",
        "group": "beaconing",
        "dtype": "float",
        "definition": "excess kurtosis of the gap series, welford online",
        "rationale": "heavy tails distinguish a beacon that occasionally sleeps from one whose "
                     "schedule genuinely drifts",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "ls_peak_period_s",
        "group": "beaconing",
        "dtype": "float",
        "definition": "period at the largest lomb-scargle peak over 512 log-spaced trial "
                      "frequencies, after folding harmonics back to the fundamental",
        "rationale": "the harmonic fold matters: a perfectly regular impulse train has equal energy "
                     "at every harmonic, so without it a 45 second beacon reports 22.5",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "ls_peak_power",
        "group": "beaconing",
        "dtype": "float",
        "definition": "normalised lomb-scargle power at that peak, relative to the series variance",
        "rationale": "the height of the peak relative to the noise floor, and the second gate after "
                     "the false alarm probability",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "ls_fap",
        "group": "beaconing",
        "dtype": "float",
        "definition": "false alarm probability of the peak, 1 - (1 - exp(-z)) ** 512",
        "rationale": "this is what makes the detector statistical rather than a threshold on "
                     "regularity. it answers how often noise alone would produce a peak this tall. "
                     "the alert gate is 1e-3, and the honest caveat is that a sparsely binned "
                     "impulse train normalises imperfectly, so the effective rate is nearer 2e-3",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "dst_stability",
        "group": "beaconing",
        "dtype": "float",
        "definition": "one divided by the number of distinct beacon-candidate destinations this "
                      "source has, estimated by hyperloglog",
        "rationale": "a scheduled channel to one destination is a beacon. the same schedule spread "
                     "across many destinations is a polling client, and this is the term that "
                     "separates them",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "beacon_sample_count",
        "group": "beaconing",
        "dtype": "float",
        "definition": "number of inter-arrival samples in the ring at evaluation time, at most 64",
        "rationale": "the periodogram is only assessed at 12 or more, and the count is reported "
                     "because confidence in a period genuinely depends on how many beats built it",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "beacon_span_s",
        "group": "beaconing",
        "dtype": "float",
        "definition": "total seconds covered by the samples in the ring",
        "rationale": "sets the lowest frequency the grid can test. no period longer than half this "
                     "span is representable, which is the honest ceiling on what the detector can "
                     "claim",
        "threat_class": "c2-beaconing",
    },
    {
        "name": "qname_char_entropy",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "shannon entropy in bits over the characters of the registrable label, that is "
                      "the label immediately left of the public suffix",
        "rationale": "scored on the registrable label rather than the whole name so that a long "
                     "benign hostname is not penalised for its structure. measured means on the "
                     "local corpus: benign 2.91, algorithmic dga 3.55, dictionary dga 3.04",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "qname_bigram_ll",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "mean natural-log transition probability per bigram of the registrable label "
                      "under a laplace-smoothed order-2 markov model, start and end symbols included",
        "rationale": "this is the feature that is supposed to catch dictionary dga, and the honest "
                     "measurement is that on this corpus it does not: benign labels average -2.53 "
                     "and dictionary dga -2.73, an overlap far too wide for a per-name threshold. "
                     "it separates algorithmic dga cleanly at -4.42. the dictionary family is "
                     "caught by the campaign statistics instead, and the alert says so",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "qname_len",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "length in characters of the full query name",
        "rationale": "tunnelling packs payload into the name, so length is the cheapest first "
                     "indicator. measured mean 118 on the tunnelling scenario against about 20 benign",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "label_count",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "number of dot-separated labels in the query name",
        "rationale": "encoders split payload across labels to stay inside the 63-byte label limit, "
                     "so the count rises with the payload",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "max_label_len",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "length of the longest label in the query name",
        "rationale": "a label at or near 63 characters is almost always machine-generated, and it is "
                     "the single most legible number in a tunnelling alert",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "digit_ratio",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "fraction of the registrable label that is a digit",
        "rationale": "algorithmic families drawing from a 36-character alphabet carry about 28 "
                     "percent digits. real brand labels rarely carry any",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "consonant_run_max",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "longest run of non-vowel alphanumeric characters in the registrable label, "
                      "digits counted as non-vowels",
        "rationale": "pronounceability without a language model. random draws produce runs that "
                     "human-chosen names do not",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "dga_entropy_component",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "clamped (qname_char_entropy - 3.20) / 0.60",
        "rationale": "the entropy half of the name score, reported separately so an alert can say "
                     "which of the two statistics actually carried it",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "dga_bigram_component",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "clamped (-3.20 - qname_bigram_ll) / 1.00",
        "rationale": "the bigram half of the name score, likewise reported separately",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "dga_name_score",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "0.40 times dga_entropy_component plus 0.60 times dga_bigram_component",
        "rationale": "the weighted combination the specification asks for. the bigram term is "
                     "weighted higher because it is the term that would generalise to families the "
                     "entropy term misses, even though on this corpus it does not reach the "
                     "dictionary family",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "dga_mean_name_score",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "mean dga_name_score across every query this source made in the 300 second "
                      "window",
        "rationale": "one odd name is noise, a hundred is a campaign. averaging over the source is "
                     "what makes the score usable as a gate",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "nx_response_ratio",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "fraction of dns responses to this source whose rcode is 3, nxdomain, over "
                      "the 300 second window",
        "rationale": "the strongest passive dga signal there is and it costs nothing. a generation "
                     "algorithm registers a few of the names it tries, so the rest do not exist. "
                     "measured 97 percent on both dga families and 0 percent on benign traffic. it "
                     "needs no reputation lookup, so it is compatible with a read-only tap",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "empty_answer_ratio",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "fraction of dns responses to this source that returned rcode 0 with no answer "
                      "records, the nodata case, over the same 300 second window",
        "rationale": "kept separate from nxdomain on purpose. a noerror answer with no records is "
                     "ordinary, an aaaa lookup on a v4-only name being the common case, so folding "
                     "it into the nxdomain ratio would inflate the one signal the dictionary branch "
                     "leans on",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "distinct_regdom_300s",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "distinct registrable domains this source queried in a rotating 300 second "
                      "hyperloglog window",
        "rationale": "the campaign shape. measured 554 and 376 for the two dga hosts against a "
                     "maximum of 7 for any benign host in the baseline capture",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "source_query_count_300s",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "dns queries issued by this source in the window",
        "rationale": "the denominator behind every ratio in this group, and a floor that stops a "
                     "handful of queries producing a confident-looking ratio",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "subdomain_cardinality",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "distinct full query names seen for one (source, registrable domain) pair in a "
                      "rotating 300 second hyperloglog window",
        "rationale": "the tunnelling signal, and the reason it survives encoding evasion: the count "
                     "is over labels, so base32, base64 or any other encoding changes what the "
                     "labels say without changing how many there are. measured about 2200 on the "
                     "tunnelling scenario against 1 for a normal host and zone",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "subdomain_baseline",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "exponentially weighted mean of the peak subdomain_cardinality this (source, "
                      "zone) pair reached in each earlier 300 second window, alpha 0.05, updated on "
                      "the observation path so it learns from traffic that never alerts",
        "rationale": "the adaptive part. a zone that has always had high cardinality for this host "
                     "stops being news, which is what keeps a legitimate wildcard zone quiet without "
                     "needing it on the allowlist",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "subdomain_baseline_windows",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "how many earlier 300 second windows have contributed to subdomain_baseline "
                      "for this (source, zone) pair",
        "rationale": "the rule only applies the excess clause once this reaches 2, so an alert never "
                     "quotes a ratio against a baseline that was never learned",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "subdomain_excess",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "subdomain_cardinality divided by subdomain_baseline, and exactly 1.0 while no "
                      "baseline has been learned for the pair",
        "rationale": "the quantity the rule actually tests once a baseline exists, so that the "
                     "threshold is relative to this pair rather than a global constant. it is 1.0 "
                     "rather than the raw count on a first sighting so that nothing reads as a "
                     "multiple of a baseline that is not there",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "qtype_txt_null_ratio",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "fraction of queries for this (source, registrable domain) pair in the window "
                      "whose qtype is txt (16) or null (10)",
        "rationale": "tunnels need a record type that can carry bytes back. measured 100 percent on "
                     "the tunnelling scenario and 0 percent across every benign host",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "qtype_txt_null_dev",
        "group": "dga-dns",
        "dtype": "float",
        "definition": "qtype_txt_null_ratio minus this source/domain pair's exponentially weighted baseline "
                      "for the same ratio",
        "rationale": "a host that legitimately uses txt lookups all day should not alert on the "
                     "ratio alone, so the anomaly is measured against the host's own history",
        "threat_class": "dga-dns-tunnelling",
    },
    {
        "name": "fingerprint_consistency_score",
        "group": "encrypted",
        "dtype": "float",
        "definition": "1.0 when the tcp fingerprint family matches the family the reference table "
                      "expects for this ja4, 0.0 when it contradicts it, 0.5 when the ja4 is not in "
                      "the table and no claim is made",
        "rationale": "the cross-layer check, and the best original idea in the build. the ja4 is "
                     "chosen by the tls library in user space and the tcp fingerprint by the "
                     "operating system kernel. a chrome-on-windows ja4 arriving on a linux tcp "
                     "stack means one of the two is lying, and reaching that conclusion needs no "
                     "destination reputation data, which matters because a reputation lookup would "
                     "be an outbound request and would break the read-only ingest constraint",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "ja4_tcp_pair_share",
        "group": "encrypted",
        "dtype": "float",
        "definition": "count-min estimate of how often this (ja4, tcp family) pair was seen divided "
                      "by how often this ja4 was seen at all, on this link",
        "rationale": "the corpus-free fallback. when the reference table has never seen a ja4, the "
                     "link itself still says which kernel that library normally sits on, and a "
                     "minority pairing is suspicious without any external data at all",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "ja4_observation_count",
        "group": "encrypted",
        "dtype": "float",
        "definition": "count-min estimate of how many client hellos carried this ja4",
        "rationale": "a minority share is only meaningful with support behind it, and count-min "
                     "estimates are upper bounds, which is stated in the alert",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "tls_version",
        "group": "encrypted",
        "dtype": "int",
        "definition": "negotiated tls version from the client hello, preferring the supported "
                      "versions extension over the legacy field",
        "rationale": "an old version offered by a modern-looking stack is itself inconsistent",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "tls_ext_count",
        "group": "encrypted",
        "dtype": "int",
        "definition": "number of extensions in the client hello after grease values are removed",
        "rationale": "part of the ja4 head, kept separately because the model layer benefits from "
                     "the number rather than the string",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "tls_alpn_is_h2",
        "group": "encrypted",
        "dtype": "bool",
        "definition": "1 when the first alpn value offered is h2",
        "rationale": "a browser-shaped ja4 that never offers http/2 is worth a second look. no "
                     "payload is read to obtain this, only the extension",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "splt_len",
        "group": "encrypted",
        "dtype": "int",
        "definition": "number of (signed length, inter-arrival) samples collected for this flow, at "
                      "most 20",
        "rationale": "the sequence length the tier-2 model receives, and short sequences must be "
                     "scored differently from full ones",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "splt_mean_abs_len",
        "group": "encrypted",
        "dtype": "float",
        "definition": "mean absolute packet length across the splt sequence",
        "rationale": "summarises the sequence for the rule layer while the full sequence goes to the "
                     "model layer. the sign carries direction, so the absolute value is taken here",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "splt_len_cv",
        "group": "encrypted",
        "dtype": "float",
        "definition": "coefficient of variation of the absolute packet lengths",
        "rationale": "a command channel sends near-identical records, a browser session does not",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "splt_iat_mean",
        "group": "encrypted",
        "dtype": "float",
        "definition": "mean inter-arrival in seconds across the splt sequence",
        "rationale": "the timing half of packet size and timing, which is what the problem statement "
                     "names as usable metadata for encrypted sessions",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "splt_iat_cv",
        "group": "encrypted",
        "dtype": "float",
        "definition": "coefficient of variation of those inter-arrivals",
        "rationale": "machine-driven exchanges are far more regular than interactive ones, and this "
                     "is the cheapest way to say so",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "splt_up_down_ratio",
        "group": "encrypted",
        "dtype": "float",
        "definition": "sum of forward lengths divided by sum of reverse lengths in the splt sequence",
        "rationale": "the first twenty packets already show whether a session is a download or an "
                     "upload, before any volume threshold could",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "splt_direction_changes",
        "group": "encrypted",
        "dtype": "float",
        "definition": "number of times the sign of the packet length flips across the sequence",
        "rationale": "a request-response channel alternates on nearly every packet, bulk transfer "
                     "almost never does",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "vertical_fanout_1s",
        "group": "scan",
        "dtype": "float",
        "definition": "distinct destination ports one source probed on one destination host within a "
                      "rotating one second hyperloglog window",
        "rationale": "the fast-scan scale. tens of ports inside a single second is what separates an "
                     "nmap sweep from a slow scan, and it is what chooses the sub-type",
        "threat_class": "recon-scanning",
    },
    {
        "name": "vertical_fanout_60s",
        "group": "scan",
        "dtype": "float",
        "definition": "the same count over a rotating 60 second window",
        "rationale": "the working scale. measured 1024 for the fast scan and a maximum of 2 for any "
                     "benign source in the baseline capture",
        "threat_class": "recon-scanning",
    },
    {
        "name": "vertical_fanout_3600s",
        "group": "scan",
        "dtype": "float",
        "definition": "the same count over a rotating 3600 second window",
        "rationale": "the slow-scan scale. a scan at 0.7 ports per second is invisible at one second "
                     "and marginal at sixty, and only the hour window sees all 300 of its ports",
        "threat_class": "recon-scanning",
    },
    {
        "name": "horizontal_fanout_1s",
        "group": "scan",
        "dtype": "float",
        "definition": "distinct destination hosts one source probed on one port within a rotating "
                      "one second window",
        "rationale": "the fast sweep scale, kept for symmetry with the vertical family",
        "threat_class": "recon-scanning",
    },
    {
        "name": "horizontal_fanout_60s",
        "group": "scan",
        "dtype": "float",
        "definition": "the same count over a rotating 60 second window",
        "rationale": "measured 254 for the subnet sweep against a maximum of 7 for a benign browser "
                     "reaching content servers on 443",
        "threat_class": "recon-scanning",
    },
    {
        "name": "horizontal_fanout_3600s",
        "group": "scan",
        "dtype": "float",
        "definition": "the same count over a rotating 3600 second window",
        "rationale": "catches a sweep paced slowly enough to stay under the minute window",
        "threat_class": "recon-scanning",
    },
    {
        "name": "source_distinct_ports_3600s",
        "group": "scan",
        "dtype": "float",
        "definition": "distinct destination ports this source touched across all hosts in an hour",
        "rationale": "the port half of the strobe test. a strobe is defined by a small port set, not "
                     "by a large one",
        "threat_class": "recon-scanning",
    },
    {
        "name": "source_distinct_hosts_3600s",
        "group": "scan",
        "dtype": "float",
        "definition": "distinct destination hosts this source touched across all ports in an hour",
        "rationale": "the host half of the strobe test, and the breadth term the strobe score scales",
        "threat_class": "recon-scanning",
    },
    {
        "name": "strobe_score",
        "group": "scan",
        "dtype": "float",
        "definition": "clamped (source_distinct_hosts_3600s - 30) / 30 when the source touched "
                      "between 2 and 20 distinct ports overall, otherwise zero",
        "rationale": "the third pattern, never folded into the other two. a handful of ports across "
                     "a whole subnet is a service hunt, and neither the vertical nor the horizontal "
                     "threshold describes it. no committed scenario contains a strobe, so this path "
                     "is exercised by a synthetic unit test only and that is stated in the alert",
        "threat_class": "recon-scanning",
    },
    {
        "name": "rst_response_ratio",
        "group": "scan",
        "dtype": "float",
        "definition": "resets sent back to this source divided by probes it sent, per 60 second "
                      "window",
        "rationale": "closed ports answer with a reset, so a high ratio confirms the probes are "
                     "reaching a live host and being refused",
        "threat_class": "recon-scanning",
    },
    {
        "name": "probe_completion_ratio",
        "group": "scan",
        "dtype": "float",
        "definition": "syn-acks returned to this source divided by probes it sent, per 60 second "
                      "window",
        "rationale": "the false positive guard that matters most. a browser opening many connections "
                     "gets nearly all of them answered, a scanner gets almost none, and this is what "
                     "stops a busy client looking like a horizontal sweep",
        "threat_class": "recon-scanning",
    },
    {
        "name": "mean_bytes_per_probe",
        "group": "scan",
        "dtype": "float",
        "definition": "mean ip total length of the probe packets from this source in the window",
        "rationale": "probes carry no data. 44 bytes measured on both scan scenarios, and the gate "
                     "keeps real sessions out of the scan detector",
        "threat_class": "recon-scanning",
    },
    {
        "name": "scan_probe_count_60s",
        "group": "scan",
        "dtype": "float",
        "definition": "probes from this source in the 60 second window",
        "rationale": "the support behind every ratio in this group and the minimum-evidence floor",
        "threat_class": "recon-scanning",
    },
    {
        "name": "out_in_byte_ratio",
        "group": "exfil",
        "dtype": "float",
        "definition": "lifetime bytes from initiator to responder divided by bytes back, per "
                      "(initiator, responder) pair",
        "rationale": "the cumulative view. it uses flow orientation rather than any address range, "
                     "so the detector needs no notion of which subnet is inside",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "out_in_ratio_ewma",
        "group": "exfil",
        "dtype": "float",
        "definition": "exponentially weighted mean, alpha 0.2, of the per-60-second outbound to "
                      "inbound byte ratio for this pair",
        "rationale": "the detector's whole argument. a single-window byte threshold walks straight "
                     "past slow-drip exfiltration, and the measured scenario proves it: the ratio "
                     "held at 23 to 1 for 27 minutes while no single minute carried more than 55 "
                     "kilobytes",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "sustained_asymmetry_s",
        "group": "exfil",
        "dtype": "float",
        "definition": "seconds accumulated in 60 second windows whose ratio exceeded the alert "
                      "threshold",
        "rationale": "duration is what separates exfiltration from a large upload. a backup runs "
                     "asymmetric for a while, a drip runs asymmetric for hours",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "outbound_bytes_total",
        "group": "exfil",
        "dtype": "float",
        "definition": "lifetime bytes from initiator to responder for this pair",
        "rationale": "the absolute floor, so a 20 to 1 ratio on four kilobytes never alerts",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "inbound_bytes_total",
        "group": "exfil",
        "dtype": "float",
        "definition": "lifetime bytes from responder to initiator for this pair",
        "rationale": "reported alongside the ratio so a reader can see whether the denominator was "
                     "small or genuinely absent",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "peak_window_out_bytes",
        "group": "exfil",
        "dtype": "float",
        "definition": "largest outbound byte total in any single 60 second window for this pair",
        "rationale": "carried into the alert specifically so the alert can state what a single-window "
                     "threshold would have had to be set to in order to catch this, and how absurd "
                     "that value would be",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "upload_burst_score",
        "group": "exfil",
        "dtype": "float",
        "definition": "peak_window_out_bytes divided by outbound_bytes_total",
        "rationale": "the fraction of the transfer that landed in its busiest minute. near 1 is a "
                     "burst, near 0 is a drip, and it chooses the sub-type. measured 0.05 on the "
                     "drip scenario",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "dst_source_fanout_3600s",
        "group": "exfil",
        "dtype": "float",
        "definition": "distinct internal sources that reached this destination in a rotating hour, "
                      "by hyperloglog",
        "rationale": "the raw count behind the novelty score, kept because the count is easier to "
                     "argue with than the score",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "dst_novelty_score",
        "group": "exfil",
        "dtype": "float",
        "definition": "1 minus log1p(fanout - 1) divided by log1p(8), clamped to 0..1",
        "rationale": "a destination that exactly one host talks to is more interesting than a shared "
                     "content network. it contributes to confidence rather than gating the alert, "
                     "because a legitimate single-user destination is common and should not be "
                     "silently required",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "peer_age_s",
        "group": "exfil",
        "dtype": "float",
        "definition": "seconds since the first packet observed for this (initiator, responder) pair",
        "rationale": "first-seen recency. a pair minutes old carrying a sustained upload is a "
                     "different proposition from one that has existed all week",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "reverse_direction_observed",
        "group": "exfil",
        "dtype": "bool",
        "definition": "1 when any bytes were seen from the responder for this pair",
        "rationale": "on a unidirectional tap the reverse direction may simply not be on the link. "
                     "when it is zero the ratio is a lower bound rather than a measurement, the "
                     "alert says so, and the case is counted toward the unclassifiable coverage "
                     "figure rather than being quietly asserted",
        "threat_class": "data-exfiltration",
    },
    {
        "name": "ja4_reference_support_hosts",
        "group": "encrypted",
        "dtype": "float",
        "definition": "number of distinct hosts in the baseline capture that backed the reference "
                      "table's expected pairing for this ja4",
        "rationale": "evidence-only. a disagreement against a pairing backed by 21 hosts deserves "
                     "more confidence than one backed by 2, and the number is in the alert",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "host_fingerprint_repeats",
        "group": "encrypted",
        "dtype": "float",
        "definition": "consecutive syns from this source that carried the same tcp fingerprint",
        "rationale": "evidence-only. a host with one stable kernel fingerprint makes the "
                     "contradiction unambiguous, and a host whose fingerprint wobbles does not",
        "threat_class": "encrypted-malware",
    },
    {
        "name": "sampling_active",
        "group": "context",
        "dtype": "bool",
        "definition": "1 when the ingest path was sampling rather than seeing every packet at the "
                      "moment the alert was raised",
        "rationale": "an alert raised under degraded operation must say so. every rate and "
                     "cardinality in it is scaled by the sampling ratio and is therefore weaker "
                     "evidence than the same number taken at full rate",
        "threat_class": "all",
    },
    {
        "name": "sampling_ratio",
        "group": "context",
        "dtype": "float",
        "definition": "fraction of packets actually processed, 1.0 when nothing was dropped",
        "rationale": "makes the degradation quantitative rather than a boolean, so a reader can "
                     "reason about what the true rate probably was",
        "threat_class": "all",
    },
    {
        "name": "shedding_tier",
        "group": "context",
        "dtype": "int",
        "definition": "0 for full processing, rising as stages are shed under load",
        "rationale": "says which stages were still running. an alert raised at a high shedding tier "
                     "was produced by fewer detectors than one raised at tier 0",
        "threat_class": "all",
    },
]

FEATURES_BY_NAME: dict[str, dict[str, Any]] = {row["name"]: row for row in FEATURES}

FEATURES_BY_GROUP: dict[str, list[dict[str, Any]]] = {
    group: [row for row in FEATURES if row["group"] == group] for group in GROUPS
}

COUNT = len(FEATURES)

COUNT_NOTE = (
    "the build specification estimated about 52 features. this registry documents {0}. the extra "
    "come from three ddos sub-types rather than two, three scan scales rather than one, the "
    "campaign-level dns statistics that catch the dictionary family, and splitting each composite "
    "score into the components that produced it so an alert can say which half fired"
).format(COUNT)


def names() -> list[str]:
    return [row["name"] for row in FEATURES]


def feature(name: str) -> dict[str, Any]:
    return FEATURES_BY_NAME[name]


def unregistered(values: dict[str, float]) -> list[str]:
    return sorted(name for name in values if name not in FEATURES_BY_NAME)


def as_markdown_rows() -> list[tuple[str, str, str, str, str, str]]:
    return [
        (row["name"], row["group"], row["dtype"], row["definition"], row["rationale"],
         row["threat_class"])
        for row in FEATURES
    ]
