# Feature Dictionary

Generated from `engine/features/registry.py` by `tools/gen_features_md.py`. Do not
edit this file by hand: edit the registry and regenerate, otherwise the
documentation and the code drift apart.

    python tools/gen_features_md.py

This is deliverable requirement R14. Every feature the engine computes is listed
here with its definition, the reason it exists, and the threat class it serves.
A test in `tests/test_detectors.py` asserts that every feature any detector emits,
and every feature name that appears in any alert's evidence, is present in the
registry, so this list cannot fall behind the code.

Feature count: **104**.

the build specification estimated about 52 features. this registry documents 104. the extra come
from three ddos sub-types rather than two, three scan scales rather than one, the campaign-level
dns statistics that catch the dictionary family, and splitting each composite score into the
components that produced it so an alert can say which half fired.

| Group | Features |
|---|---|
| Flow-structural | 11 |
| Volumetric and protocol DDoS, class (a) | 18 |
| Botnet C2 beaconing, class (b) | 11 |
| DGA domains and DNS tunnelling, class (c) | 21 |
| Malware in encrypted sessions, class (d) | 15 |
| Reconnaissance and port scanning, class (e) | 13 |
| Data exfiltration, class (f) | 11 |
| Detection context | 4 |
| **Total** | **104** |

## Flow-structural

Read by every detector. Threat class is 'all' because these describe the flow, not an attack.

**`duration`** - float - all

seconds between the first and last packet observed for this flow key.

Why: separates a completed session from a probe and bounds every rate this flow contributes to.

**`pkts_fwd`** - int - all

packets sent by the flow initiator, after the orientation bit has been resolved.

Why: forward and reverse counts are only meaningful once the initiator is known, which is why
orientation is resolved before any counter is read.

**`pkts_rev`** - int - all

packets sent by the flow responder, that is back toward the initiator.

Why: a zero here on a tcp flow means the far side never answered, which is the shape of a scan
probe and of a spoofed-source flood.

**`bytes_fwd`** - int - all

ip total-length bytes sent by the initiator.

Why: the numerator of every asymmetry ratio in the exfiltration detector.

**`bytes_rev`** - int - all

ip total-length bytes sent by the responder.

Why: the denominator of every asymmetry ratio, and zero means the ratio is a lower bound rather
than a measurement.

**`bytes_per_pkt_fwd`** - float - all

bytes_fwd divided by pkts_fwd, the mean forward packet size.

Why: probes and keepalives are tiny, bulk transfer is near the mtu, and the two do not overlap.

**`bytes_per_pkt_rev`** - float - all

bytes_rev divided by pkts_rev, the mean reverse packet size.

Why: large reverse packets against tiny forward packets is the amplification shape.

**`flags_seen_bitmap`** - int - volumetric-ddos

bitwise or of every tcp flag byte observed on the flow.

Why: a flow that never carried fin or rst never closed, which is what connection exhaustion
looks like from outside.

**`completeness_flag`** - bool - all

true when packets were observed in both directions.

Why: on a one-way tap this is the honest marker of whether a ratio was measured or assumed, and
it is carried into the alert.

**`directionality`** - bool - all

1 when both directions were seen, 0 when only one was.

Why: the numeric form of completeness_flag for the model layer.

**`orientation_confidence`** - float - all

1.0 when a syn or syn-ack fixed the initiator, 0.5 when it was inferred from the first packet
seen, 0.0 when unknown.

Why: a mid-flow pickup can be oriented backwards, and every downstream ratio inherits that
doubt, so it is reported rather than hidden.

## Volumetric and protocol DDoS, class (a)

The PS names flow rate statistics and source-IP entropy for this class. Both are here, plus the
two features that tell the sub-types apart.

**`pps_to_dst`** - float - volumetric-ddos

packets per second arriving at one destination address, measured over the one-second bucket that
just closed.

Why: the raw rate. it is reported next to the deviation so a reader can see whether a large
sigma came from a large rate or from a very quiet baseline.

**`pps_to_dst_ewma_dev`** - float - volumetric-ddos

(pps - baseline mean) divided by sqrt(max(baseline variance, baseline mean, 1)). the baseline is
a per-destination ewma with alpha 0.1 whose update is clipped at 4 sigma, and it falls back to
the enclave-wide per-destination rate prior until the destination has 5 observations of its own.

Why: three deliberate choices. the poisson floor stops a perfectly steady baseline producing a
zero or infinite z-score. the clipped update stops an attack training the detector to accept
itself. the population fallback lets a first-seen destination be judged at all, and the alert
says which baseline was used.

**`src_entropy_1s`** - float - volumetric-ddos

shannon entropy of source addresses reaching this destination in a one-second sliding window,
normalised by log of the distinct count, so 0..1.

Why: the problem statement names source-ip entropy directly. normalised entropy saturates near
1.0 for both 35 and 140 uniform sources, which is exactly why it is not used alone.

**`src_entropy_ratio_1s`** - float - volumetric-ddos

entropy in bits divided by log2 of the smaller of the packet count and the 512 slots the sliding
counter holds, so the ceiling is the entropy actually reachable rather than the one a bigger
flood would need.

Why: the fraction of the reachable entropy the window carries. it approaches 1 when nearly every
packet brings a fresh source, which is the spoofed-flood signature, and it stays there as the
flood gets faster instead of decaying.

**`src_cardinality_1s`** - float - volumetric-ddos

distinct source addresses to this destination in one second, counted in a 512-slot sliding table
allocated only for destinations above 8 packets/s.

Why: lazy allocation keeps the per-destination entropy state off the 99 percent of destinations
that never carry a flood.

**`src_cardinality_60s`** - float - volumetric-ddos

distinct source addresses to this destination over a rotating 60 second hyperloglog, so the
window covers between 60 and 120 seconds.

Why: the wide-window count is what reveals whether the source set is growing or has saturated.

**`src_cardinality_growth`** - float - volumetric-ddos

src_cardinality_60s divided by src_cardinality_1s.

Why: the discriminant between the two sub-types, and the strongest one available. a spoofed
flood draws from an effectively unbounded address space so the ratio grows with the window
(measured 21 on the syn flood scenario). reflection draws from a finite reflector list so it
saturates (measured 1.4). fifteen times apart, and it is a physical difference, not a tuned
threshold.

**`entropy_explosion_score`** - float - volumetric-ddos

clamped (src_entropy_ratio_1s - 0.55) / 0.35 multiplied by clamped (src_cardinality_growth - 2)
/ 6, zero when no entropy state exists.

Why: the spoofed-source flood score. both factors must hold: the window must be near-maximally
diverse and the diversity must keep growing. measured 1.00 on the syn flood scenario and 0.00 on
the reflection scenario.

**`entropy_collapse_score`** - float - volumetric-ddos

clamped (3 - src_cardinality_growth) / 2 multiplied by clamped (mean_pkt_bytes_1s - 120) / 280,
forced to zero below 3 distinct sources.

Why: the reflection and amplification score. a saturated source set carrying large replies.
measured 0.76 to 0.99 on the reflection scenario and 0.00 on the syn flood. the two sub-types
call for opposite responses, so they are never collapsed into one number.

**`syn_synack_ratio_1s`** - float - volumetric-ddos

syns arriving at this destination divided by syn-acks leaving it, per second, floored at one
syn-ack.

Why: orientation matters here. syns are counted toward the destination and syn-acks away from
it, because on a spoofed flood the syn-acks are addressed to the forged sources and never come
back to the same key.

**`udp_packet_share`** - float - volumetric-ddos

Fraction of packets in the completed destination bucket whose transport is UDP..

Why: Prevents TCP transfers from satisfying a UDP reflection rule; retained as rule evidence,
excluded from the existing trained feature contract..

**`reflection_service_share`** - float - volumetric-ddos

Fraction of UDP packets arriving from a configured possible reflection service port..

Why: Adds transport and service context to inbound byte asymmetry; a port alone does not prove
reflection. Excluded from the existing trained feature contract..

**`udp_egress_observed`** - bool - volumetric-ddos

One when any outbound UDP bytes were observed for this destination in the rate window..

Why: Makes a missing denominator visible instead of claiming a measured request/reply
amplification factor. Excluded from the existing trained feature contract..

**`amplification_ratio`** - float - volumetric-ddos

observed UDP bytes arriving at this destination divided by max(1, observed UDP bytes sent), over
a 60 second tumbling window.

Why: UDP byte asymmetry is supporting evidence, not a matched request/reply factor; a missing
return path can inflate it. TCP bytes are excluded..

**`mean_pkt_bytes_1s`** - float - volumetric-ddos

mean ip total length of packets to this destination in the last second.

Why: 44 bytes is a bare syn, 508 is a dns any reply. the packet size alone splits the flood sub-
types before any entropy is computed.

**`half_open_60s`** - float - volumetric-ddos

syns to this destination minus fins and rsts seen for it, over a 60 second tumbling window,
floored at zero.

Why: a proxy for concurrent connections held open. it is the only rate-independent ddos signal
here, which is what makes slowloris visible at 19 packets/s.

**`teardown_ratio_60s`** - float - volumetric-ddos

fins plus rsts divided by syns for this destination over the same window.

Why: healthy traffic closes what it opens. a ratio near zero with hundreds of syns means the
connections are being held deliberately.

**`concurrent_src_ports_60s`** - float - volumetric-ddos

distinct (source address, source port) pairs seen for this destination over a rotating 60 second
hyperloglog.

Why: the closest passive estimate of how many sockets a destination is being asked to hold,
which is the resource connection exhaustion actually consumes.

## Botnet C2 beaconing, class (b)

The PS names periodicity and inter-arrival analysis. The periodogram features are computed only
for candidates that pass the beacon pre-filter.

**`iat_mean`** - float - c2-beaconing

mean gap in seconds between consecutive session starts on one (client, server, port) channel,
over the 64-sample ring.

Why: the naive period estimate. it is reported so a reader can see when the periodogram and the
mean disagree, which happens when beats are dropped.

**`iat_std`** - float - c2-beaconing

population standard deviation of those gaps, welford online.

Why: the jitter budget in absolute seconds, which is what an analyst needs to decide whether a
schedule is tight or loose.

**`iat_cv`** - float - c2-beaconing

iat_std divided by iat_mean, the scale-free measure of schedule jitter.

Why: the fallback statistic. when an implant sleeps for period times a random factor the phase
becomes a random walk and no periodogram can hold coherence, but the coefficient of variation
still separates a scheduled channel from human traffic. measured 0.17 on the 30 percent jittered
beacon.

**`iat_skew`** - float - c2-beaconing

third standardised moment of the gap series, welford online.

Why: a long right tail means missed check-ins rather than a different period.

**`iat_kurtosis`** - float - c2-beaconing

excess kurtosis of the gap series, welford online.

Why: heavy tails distinguish a beacon that occasionally sleeps from one whose schedule genuinely
drifts.

**`ls_peak_period_s`** - float - c2-beaconing

period at the largest lomb-scargle peak over 512 log-spaced trial frequencies, after folding
harmonics back to the fundamental.

Why: the harmonic fold matters: a perfectly regular impulse train has equal energy at every
harmonic, so without it a 45 second beacon reports 22.5.

**`ls_peak_power`** - float - c2-beaconing

normalised lomb-scargle power at that peak, relative to the series variance.

Why: the height of the peak relative to the noise floor, and the second gate after the false
alarm probability.

**`ls_fap`** - float - c2-beaconing

false alarm probability of the peak, 1 - (1 - exp(-z)) ** 512.

Why: this is what makes the detector statistical rather than a threshold on regularity. it
answers how often noise alone would produce a peak this tall. the alert gate is 1e-3, and the
honest caveat is that a sparsely binned impulse train normalises imperfectly, so the effective
rate is nearer 2e-3.

**`dst_stability`** - float - c2-beaconing

one divided by the number of distinct beacon-candidate destinations this source has, estimated
by hyperloglog.

Why: a scheduled channel to one destination is a beacon. the same schedule spread across many
destinations is a polling client, and this is the term that separates them.

**`beacon_sample_count`** - float - c2-beaconing

number of inter-arrival samples in the ring at evaluation time, at most 64.

Why: the periodogram is only assessed at 12 or more, and the count is reported because
confidence in a period genuinely depends on how many beats built it.

**`beacon_span_s`** - float - c2-beaconing

total seconds covered by the samples in the ring.

Why: sets the lowest frequency the grid can test. no period longer than half this span is
representable, which is the honest ceiling on what the detector can claim.

## DGA domains and DNS tunnelling, class (c)

The PS names entropy and n-gram analysis of query names. The campaign-level counters are here
because the n-gram score alone does not separate the dictionary family.

**`qname_char_entropy`** - float - dga-dns-tunnelling

shannon entropy in bits over the characters of the registrable label, that is the label
immediately left of the public suffix.

Why: scored on the registrable label rather than the whole name so that a long benign hostname
is not penalised for its structure. measured means on the local corpus: benign 2.91, algorithmic
dga 3.55, dictionary dga 3.04.

**`qname_bigram_ll`** - float - dga-dns-tunnelling

mean natural-log transition probability per bigram of the registrable label under a laplace-
smoothed order-2 markov model, start and end symbols included.

Why: this is the feature that is supposed to catch dictionary dga, and the honest measurement is
that on this corpus it does not: benign labels average -2.53 and dictionary dga -2.73, an
overlap far too wide for a per-name threshold. it separates algorithmic dga cleanly at -4.42.
the dictionary family is caught by the campaign statistics instead, and the alert says so.

**`qname_len`** - float - dga-dns-tunnelling

length in characters of the full query name.

Why: tunnelling packs payload into the name, so length is the cheapest first indicator. measured
mean 118 on the tunnelling scenario against about 20 benign.

**`label_count`** - float - dga-dns-tunnelling

number of dot-separated labels in the query name.

Why: encoders split payload across labels to stay inside the 63-byte label limit, so the count
rises with the payload.

**`max_label_len`** - float - dga-dns-tunnelling

length of the longest label in the query name.

Why: a label at or near 63 characters is almost always machine-generated, and it is the single
most legible number in a tunnelling alert.

**`digit_ratio`** - float - dga-dns-tunnelling

fraction of the registrable label that is a digit.

Why: algorithmic families drawing from a 36-character alphabet carry about 28 percent digits.
real brand labels rarely carry any.

**`consonant_run_max`** - float - dga-dns-tunnelling

longest run of non-vowel alphanumeric characters in the registrable label, digits counted as
non-vowels.

Why: pronounceability without a language model. random draws produce runs that human-chosen
names do not.

**`dga_entropy_component`** - float - dga-dns-tunnelling

clamped (qname_char_entropy - 3.20) / 0.60.

Why: the entropy half of the name score, reported separately so an alert can say which of the
two statistics actually carried it.

**`dga_bigram_component`** - float - dga-dns-tunnelling

clamped (-3.20 - qname_bigram_ll) / 1.00.

Why: the bigram half of the name score, likewise reported separately.

**`dga_name_score`** - float - dga-dns-tunnelling

0.40 times dga_entropy_component plus 0.60 times dga_bigram_component.

Why: the weighted combination the specification asks for. the bigram term is weighted higher
because it is the term that would generalise to families the entropy term misses, even though on
this corpus it does not reach the dictionary family.

**`dga_mean_name_score`** - float - dga-dns-tunnelling

mean dga_name_score across every query this source made in the 300 second window.

Why: one odd name is noise, a hundred is a campaign. averaging over the source is what makes the
score usable as a gate.

**`nx_response_ratio`** - float - dga-dns-tunnelling

fraction of dns responses to this source whose rcode is 3, nxdomain, over the 300 second window.

Why: the strongest passive dga signal there is and it costs nothing. a generation algorithm
registers a few of the names it tries, so the rest do not exist. measured 97 percent on both dga
families and 0 percent on benign traffic. it needs no reputation lookup, so it is compatible
with a read-only tap.

**`empty_answer_ratio`** - float - dga-dns-tunnelling

fraction of dns responses to this source that returned rcode 0 with no answer records, the
nodata case, over the same 300 second window.

Why: kept separate from nxdomain on purpose. a noerror answer with no records is ordinary, an
aaaa lookup on a v4-only name being the common case, so folding it into the nxdomain ratio would
inflate the one signal the dictionary branch leans on.

**`distinct_regdom_300s`** - float - dga-dns-tunnelling

distinct registrable domains this source queried in a rotating 300 second hyperloglog window.

Why: the campaign shape. measured 554 and 376 for the two dga hosts against a maximum of 7 for
any benign host in the baseline capture.

**`source_query_count_300s`** - float - dga-dns-tunnelling

dns queries issued by this source in the window.

Why: the denominator behind every ratio in this group, and a floor that stops a handful of
queries producing a confident-looking ratio.

**`subdomain_cardinality`** - float - dga-dns-tunnelling

distinct full query names seen for one (source, registrable domain) pair in a rotating 300
second hyperloglog window.

Why: the tunnelling signal, and the reason it survives encoding evasion: the count is over
labels, so base32, base64 or any other encoding changes what the labels say without changing how
many there are. measured about 2200 on the tunnelling scenario against 1 for a normal host and
zone.

**`subdomain_baseline`** - float - dga-dns-tunnelling

exponentially weighted mean of the peak subdomain_cardinality this (source, zone) pair reached
in each earlier 300 second window, alpha 0.05, updated on the observation path so it learns from
traffic that never alerts.

Why: the adaptive part. a zone that has always had high cardinality for this host stops being
news, which is what keeps a legitimate wildcard zone quiet without needing it on the allowlist.

**`subdomain_baseline_windows`** - float - dga-dns-tunnelling

how many earlier 300 second windows have contributed to subdomain_baseline for this (source,
zone) pair.

Why: the rule only applies the excess clause once this reaches 2, so an alert never quotes a
ratio against a baseline that was never learned.

**`subdomain_excess`** - float - dga-dns-tunnelling

subdomain_cardinality divided by subdomain_baseline, and exactly 1.0 while no baseline has been
learned for the pair.

Why: the quantity the rule actually tests once a baseline exists, so that the threshold is
relative to this pair rather than a global constant. it is 1.0 rather than the raw count on a
first sighting so that nothing reads as a multiple of a baseline that is not there.

**`qtype_txt_null_ratio`** - float - dga-dns-tunnelling

fraction of queries for this (source, registrable domain) pair in the window whose qtype is txt
(16) or null (10).

Why: tunnels need a record type that can carry bytes back. measured 100 percent on the
tunnelling scenario and 0 percent across every benign host.

**`qtype_txt_null_dev`** - float - dga-dns-tunnelling

qtype_txt_null_ratio minus this source/domain pair's exponentially weighted baseline for the
same ratio.

Why: a host that legitimately uses txt lookups all day should not alert on the ratio alone, so
the anomaly is measured against the host's own history.

## Malware in encrypted sessions, class (d)

TLS metadata only. Nothing in this group is derived from application data, and no feature here
needs a lookup of any kind.

**`fingerprint_consistency_score`** - float - encrypted-malware

1.0 when the tcp fingerprint family matches the family the reference table expects for this ja4,
0.0 when it contradicts it, 0.5 when the ja4 is not in the table and no claim is made.

Why: the cross-layer check, and the best original idea in the build. the ja4 is chosen by the
tls library in user space and the tcp fingerprint by the operating system kernel. a chrome-on-
windows ja4 arriving on a linux tcp stack means one of the two is lying, and reaching that
conclusion needs no destination reputation data, which matters because a reputation lookup would
be an outbound request and would break the read-only ingest constraint.

**`ja4_tcp_pair_share`** - float - encrypted-malware

count-min estimate of how often this (ja4, tcp family) pair was seen divided by how often this
ja4 was seen at all, on this link.

Why: the corpus-free fallback. when the reference table has never seen a ja4, the link itself
still says which kernel that library normally sits on, and a minority pairing is suspicious
without any external data at all.

**`ja4_observation_count`** - float - encrypted-malware

count-min estimate of how many client hellos carried this ja4.

Why: a minority share is only meaningful with support behind it, and count-min estimates are
upper bounds, which is stated in the alert.

**`tls_version`** - int - encrypted-malware

negotiated tls version from the client hello, preferring the supported versions extension over
the legacy field.

Why: an old version offered by a modern-looking stack is itself inconsistent.

**`tls_ext_count`** - int - encrypted-malware

number of extensions in the client hello after grease values are removed.

Why: part of the ja4 head, kept separately because the model layer benefits from the number
rather than the string.

**`tls_alpn_is_h2`** - bool - encrypted-malware

1 when the first alpn value offered is h2.

Why: a browser-shaped ja4 that never offers http/2 is worth a second look. no payload is read to
obtain this, only the extension.

**`splt_len`** - int - encrypted-malware

number of (signed length, inter-arrival) samples collected for this flow, at most 20.

Why: the sequence length the tier-2 model receives, and short sequences must be scored
differently from full ones.

**`splt_mean_abs_len`** - float - encrypted-malware

mean absolute packet length across the splt sequence.

Why: summarises the sequence for the rule layer while the full sequence goes to the model layer.
the sign carries direction, so the absolute value is taken here.

**`splt_len_cv`** - float - encrypted-malware

coefficient of variation of the absolute packet lengths.

Why: a command channel sends near-identical records, a browser session does not.

**`splt_iat_mean`** - float - encrypted-malware

mean inter-arrival in seconds across the splt sequence.

Why: the timing half of packet size and timing, which is what the problem statement names as
usable metadata for encrypted sessions.

**`splt_iat_cv`** - float - encrypted-malware

coefficient of variation of those inter-arrivals.

Why: machine-driven exchanges are far more regular than interactive ones, and this is the
cheapest way to say so.

**`splt_up_down_ratio`** - float - encrypted-malware

sum of forward lengths divided by sum of reverse lengths in the splt sequence.

Why: the first twenty packets already show whether a session is a download or an upload, before
any volume threshold could.

**`splt_direction_changes`** - float - encrypted-malware

number of times the sign of the packet length flips across the sequence.

Why: a request-response channel alternates on nearly every packet, bulk transfer almost never
does.

**`ja4_reference_support_hosts`** - float - encrypted-malware

number of distinct hosts in the baseline capture that backed the reference table's expected
pairing for this ja4.

Why: evidence-only. a disagreement against a pairing backed by 21 hosts deserves more confidence
than one backed by 2, and the number is in the alert.

**`host_fingerprint_repeats`** - float - encrypted-malware

consecutive syns from this source that carried the same tcp fingerprint.

Why: evidence-only. a host with one stable kernel fingerprint makes the contradiction
unambiguous, and a host whose fingerprint wobbles does not.

## Reconnaissance and port scanning, class (e)

The PS names fan-out across ports or hosts. Vertical, horizontal and strobe fan-out are kept as
three separate features so an alert can say which pattern fired.

**`vertical_fanout_1s`** - float - recon-scanning

distinct destination ports one source probed on one destination host within a rotating one
second hyperloglog window.

Why: the fast-scan scale. tens of ports inside a single second is what separates an nmap sweep
from a slow scan, and it is what chooses the sub-type.

**`vertical_fanout_60s`** - float - recon-scanning

the same count over a rotating 60 second window.

Why: the working scale. measured 1024 for the fast scan and a maximum of 2 for any benign source
in the baseline capture.

**`vertical_fanout_3600s`** - float - recon-scanning

the same count over a rotating 3600 second window.

Why: the slow-scan scale. a scan at 0.7 ports per second is invisible at one second and marginal
at sixty, and only the hour window sees all 300 of its ports.

**`horizontal_fanout_1s`** - float - recon-scanning

distinct destination hosts one source probed on one port within a rotating one second window.

Why: the fast sweep scale, kept for symmetry with the vertical family.

**`horizontal_fanout_60s`** - float - recon-scanning

the same count over a rotating 60 second window.

Why: measured 254 for the subnet sweep against a maximum of 7 for a benign browser reaching
content servers on 443.

**`horizontal_fanout_3600s`** - float - recon-scanning

the same count over a rotating 3600 second window.

Why: catches a sweep paced slowly enough to stay under the minute window.

**`source_distinct_ports_3600s`** - float - recon-scanning

distinct destination ports this source touched across all hosts in an hour.

Why: the port half of the strobe test. a strobe is defined by a small port set, not by a large
one.

**`source_distinct_hosts_3600s`** - float - recon-scanning

distinct destination hosts this source touched across all ports in an hour.

Why: the host half of the strobe test, and the breadth term the strobe score scales.

**`strobe_score`** - float - recon-scanning

clamped (source_distinct_hosts_3600s - 30) / 30 when the source touched between 2 and 20
distinct ports overall, otherwise zero.

Why: the third pattern, never folded into the other two. a handful of ports across a whole
subnet is a service hunt, and neither the vertical nor the horizontal threshold describes it. no
committed scenario contains a strobe, so this path is exercised by a synthetic unit test only
and that is stated in the alert.

**`rst_response_ratio`** - float - recon-scanning

resets sent back to this source divided by probes it sent, per 60 second window.

Why: closed ports answer with a reset, so a high ratio confirms the probes are reaching a live
host and being refused.

**`probe_completion_ratio`** - float - recon-scanning

syn-acks returned to this source divided by probes it sent, per 60 second window.

Why: the false positive guard that matters most. a browser opening many connections gets nearly
all of them answered, a scanner gets almost none, and this is what stops a busy client looking
like a horizontal sweep.

**`mean_bytes_per_probe`** - float - recon-scanning

mean ip total length of the probe packets from this source in the window.

Why: probes carry no data. 44 bytes measured on both scan scenarios, and the gate keeps real
sessions out of the scan detector.

**`scan_probe_count_60s`** - float - recon-scanning

probes from this source in the 60 second window.

Why: the support behind every ratio in this group and the minimum-evidence floor.

## Data exfiltration, class (f)

The PS names asymmetric outbound-to-inbound byte ratios. Orientation comes from the flow table,
so no notion of an inside subnet is needed.

**`out_in_byte_ratio`** - float - data-exfiltration

lifetime bytes from initiator to responder divided by bytes back, per (initiator, responder)
pair.

Why: the cumulative view. it uses flow orientation rather than any address range, so the
detector needs no notion of which subnet is inside.

**`out_in_ratio_ewma`** - float - data-exfiltration

exponentially weighted mean, alpha 0.2, of the per-60-second outbound to inbound byte ratio for
this pair.

Why: the detector's whole argument. a single-window byte threshold walks straight past slow-drip
exfiltration, and the measured scenario proves it: the ratio held at 23 to 1 for 27 minutes
while no single minute carried more than 55 kilobytes.

**`sustained_asymmetry_s`** - float - data-exfiltration

seconds accumulated in 60 second windows whose ratio exceeded the alert threshold.

Why: duration is what separates exfiltration from a large upload. a backup runs asymmetric for a
while, a drip runs asymmetric for hours.

**`outbound_bytes_total`** - float - data-exfiltration

lifetime bytes from initiator to responder for this pair.

Why: the absolute floor, so a 20 to 1 ratio on four kilobytes never alerts.

**`inbound_bytes_total`** - float - data-exfiltration

lifetime bytes from responder to initiator for this pair.

Why: reported alongside the ratio so a reader can see whether the denominator was small or
genuinely absent.

**`peak_window_out_bytes`** - float - data-exfiltration

largest outbound byte total in any single 60 second window for this pair.

Why: carried into the alert specifically so the alert can state what a single-window threshold
would have had to be set to in order to catch this, and how absurd that value would be.

**`upload_burst_score`** - float - data-exfiltration

peak_window_out_bytes divided by outbound_bytes_total.

Why: the fraction of the transfer that landed in its busiest minute. near 1 is a burst, near 0
is a drip, and it chooses the sub-type. measured 0.05 on the drip scenario.

**`dst_source_fanout_3600s`** - float - data-exfiltration

distinct internal sources that reached this destination in a rotating hour, by hyperloglog.

Why: the raw count behind the novelty score, kept because the count is easier to argue with than
the score.

**`dst_novelty_score`** - float - data-exfiltration

1 minus log1p(fanout - 1) divided by log1p(8), clamped to 0..1.

Why: a destination that exactly one host talks to is more interesting than a shared content
network. it contributes to confidence rather than gating the alert, because a legitimate single-
user destination is common and should not be silently required.

**`peer_age_s`** - float - data-exfiltration

seconds since the first packet observed for this (initiator, responder) pair.

Why: first-seen recency. a pair minutes old carrying a sustained upload is a different
proposition from one that has existed all week.

**`reverse_direction_observed`** - bool - data-exfiltration

1 when any bytes were seen from the responder for this pair.

Why: on a unidirectional tap the reverse direction may simply not be on the link. when it is
zero the ratio is a lower bound rather than a measurement, the alert says so, and the case is
counted toward the unclassifiable coverage figure rather than being quietly asserted.

## Detection context

Emitted into every alert so that a detection raised under load says so.

**`initiator_is_lo`** - bool - all

1 when the initiator is the lexicographically lower endpoint of the flow key.

Why: bookkeeping for the key normalisation, not a threat signal. kept out of the model because
address ordering correlates with the fixed attacker ranges of a synthetic corpus, which is
leakage rather than detection.

**`sampling_active`** - bool - all

1 when the ingest path was sampling rather than seeing every packet at the moment the alert was
raised.

Why: an alert raised under degraded operation must say so. every rate and cardinality in it is
scaled by the sampling ratio and is therefore weaker evidence than the same number taken at full
rate.

**`sampling_ratio`** - float - all

fraction of packets actually processed, 1.0 when nothing was dropped.

Why: makes the degradation quantitative rather than a boolean, so a reader can reason about what
the true rate probably was.

**`shedding_tier`** - int - all

0 for full processing, rising as stages are shed under load.

Why: says which stages were still running. an alert raised at a high shedding tier was produced
by fewer detectors than one raised at tier 0.
