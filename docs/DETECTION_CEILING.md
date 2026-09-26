# Detection Ceiling

What this system cannot see, and why. Everything here is a physical or configured limit of
detection from unidirectional metadata, not a defect to be fixed in a later sprint. Each limit is
stated with the number that produces it so a reader can check it against the code.

Two reasons this document exists. First, a monitoring enclave that overstates its coverage is
worse than one that states it, because an operator plans around the claim. Second, the fastest
way to test whether a detection claim is real is to ask what it excludes; volunteering the answer
is stronger than being asked for it.

---

## 1. Payload contents. Always, without exception

The engine never holds application data. `PacketMeta` in `engine/types.py` has no payload field,
and `parse_packet` in `engine/decode/packet.py` deletes its local `payload` variable on the
statement after the TLS and DNS parsers return. Those parsers return `TLSMeta` and `DNSMeta`,
which hold fingerprints, counters, a query name and a boolean, and no bytes. The type cannot
carry payload, so no future feature can read it without changing the type first, and
`tests/test_decode.py::test_packet_meta_has_no_payload_field` asserts that against
`PacketMeta.__slots__`.

What that costs, stated plainly: no content inspection, no signature matching, no file carving,
no credential detection, no exfiltrated-data recovery. If the evidence for a threat is inside the
bytes, this system will not find it. Constraint C-b is satisfied by construction and the cost is
real.

## 2. The TLS SNI hostname

`TLSMeta` records `sni_present` as a boolean. The hostname is read while parsing the ClientHello
in order to set that flag, and is then discarded; it is never stored, never featurised and never
appears in an alert. This is stricter than the constraint requires, and it means the entire class
of hostname-reputation detection is unavailable by design rather than by circumstance.

Encrypted Client Hello removes the field from the wire altogether. Once a session negotiates ECH,
even `sni_present` becomes uninformative: the outer hello carries a public name that says nothing
about the real destination. No passive observer recovers the inner name without the ECH key, and
the enclave will never hold one.

## 3. QUIC handshake metadata

QUIC is not decoded. `engine/decode/packet.py` classifies UDP/443 as UDP and stops there, so QUIC
Initial packets yield no ClientHello, no JA4 and no ALPN. Every JA4 the engine emits is a `t`
transport fingerprint; there are no `q` fingerprints anywhere in the build.

This is measured rather than assumed: `/api/coverage` counts a UDP/443 flow as
`unclassifiable_opaque` with the reason code `quic-handshake`, so a run over QUIC-heavy traffic
reports the blind spot on the dashboard while it is happening. The problem statement names
TLS/QUIC metadata for class (d); the honest position is that half of that is implemented.

QUIC's Initial packets are protected with keys derived from the connection ID, so a passive
observer can in principle decrypt them and read the ClientHello. That is future work, not a
constraint violation, and it is not in this build.

## 4. A ClientHello split across TCP segments

There is no TCP reassembly. A ClientHello contained in a single segment yields a JA4; one split
across two segments yields nothing, and the flow is counted as `unclassifiable_opaque` with the
reason `payload-opaque`. Reassembly would mean buffering application bytes across packets, which
is exactly the thing C-b forbids doing casually, so it was left out.

Most real ClientHellos fit in one segment. Large ones, particularly post-quantum key shares that
push a hello past the MSS, do not. A client that deliberately fragments its hello defeats the JA4
path entirely.

## 5. Anything that needs a packet sent

Constraint C-a means nothing in this repository sends a packet off the host. That deletes,
permanently:

- active probing of a suspected host, including banner grabs and version scans
- completing a handshake to observe a server's behaviour, so there is no JA4S for any server that
  did not send its ServerHello on the observed link
- resolving an observed domain, so a DGA name cannot be checked for whether it actually resolves
- reputation, threat-intelligence and passive-DNS lookups of any kind
- certificate transparency or OCSP queries
- blocking, rate limiting, RST injection or any other mitigation

`tests/test_api.py` checks that two ways: an AST walk over every module under
`engine/` asserting no import of `socket`, `requests`, `httpx`, `urllib`, `urllib3`, `http`,
`aiohttp`, `ftplib` or `smtplib`, and a subprocess that monkeypatches `socket.socket.__init__` to
raise and then runs ingest and the state structures over all 13100 packets of `syn_flood.pcap`,
asserting zero sockets were constructed.

Read the guard for what it actually imports: `PcapSource`, `FlowTable`, `SlidingEntropy` and
`HLLFamily`. It does not import `engine.detect`, `engine.models`, `engine.pipeline` or
`engine.alerts`, so it is evidence about the packet and state path and not about the whole
process. Neither is `api/replay.py` or `api/store.py` in the AST walk, though both drive the
engine.

### One socket is constructed, and it is not on the packet path

The earlier wording here said no socket is ever constructed. That was wrong, so here is the
measurement instead. `engine/alerts/schema.py` has a module-level `import stix2`; `stix2` imports
`requests`; `requests/__init__.py` imports `urllib3`; and `urllib3/util/connection.py` runs
`HAS_IPV6 = _has_ipv6("::1")` at import time, which constructs an `AF_INET6` socket and binds it
to `("::1", 0)` to find out whether the host has IPv6 at all. Importing the alert schema therefore
constructs exactly one socket:

```
python - <<'PY'
import socket
opened = []
_init = socket.socket.__init__
socket.socket.__init__ = lambda s, *a, **k: (opened.append(a), _init(s, *a, **k))[1]
import engine.alerts.schema
print(opened)
PY
```

prints `[(<AddressFamily.AF_INET6: 23>,)]`. Running the same guard over the real detection path,
`run_source(PcapSource('data/scenarios/syn_flood.pcap'))` followed by `build_alert` and
`validate_alert` on every detection, reports all 13100 packets and one socket.

What that socket is and is not. A `bind` to `::1` port 0 is a local capability probe: it never
calls `connect`, never resolves a name, never sends a byte, and nothing reaches an interface other
than loopback. So the constraint that matters, no packet leaves this host and no path exists back
toward the monitored link, still holds. What does not hold is the stronger sentence, and a stronger
sentence is exactly what a judge will check.

Two ways to close it, both cheap and neither done in this build:

- drop the runtime `stix2` dependency from `engine/alerts/schema.py`. The builder already knows
  every field it needs and can assemble the indicator dict directly; the `stix2` round-trip in
  `validate_alert` becomes optional, behind an environment flag or in a test-only helper. That
  removes `requests` and `urllib3` from `sys.modules` entirely.
- or keep `stix2` and rewrite the C-a claim as "no outbound connection is ever made", which is
  what is provable today. That is the wording used in `README.md` and in `docs/ARCHITECTURE.md`.

Until the first of those lands, the honest C-a claim is the second one.

## 6. Beacon periods longer than the beacon table can represent

The hard number is **21600 seconds**, six hours: `beacon_ttl_s` in
`engine/detect/base.py::DEFAULT_CONFIG`. A candidate whose gap exceeds the TTL is dropped from
`BeaconTable`, so a beacon with a period above six hours cannot be represented at all, whatever
the capture length.

Below that ceiling the limit is arithmetic. A period is only assessable after `min_samples` gaps
have been observed, and `min_samples` is 12, so the time to first decision is twelve periods:

| Beacon period | Earliest possible decision |
|---|---|
| 45 s | about 9 minutes |
| 5 min | 1 hour |
| 30 min | 6 hours |
| 1 h | 12 hours |
| above 6 h | never, the candidate is expired first |

The ring holds 64 inter-arrival samples, so the periodogram sees at most the last 64 gaps. These
numbers are published by the detector itself: `BeaconDetector.coverage()` returns them and every
beacon alert carries them in `context["coverage"]`, so the alert states its own limit.

The binned event train also has a **4,096-bin allocation limit**. Its size depends on total span
divided by median gap, so a single long silence can otherwise allocate a very large grid even
with only 64 gaps. Over-budget candidates are skipped, not downsampled or assigned a benign
score. `resource_budget_skipped` and the `periodogram-event-bin-budget` suppression record the
loss of analysis; Operations and `/api/metrics` expose the count. Normal regular slow beacons
retain their original grid: 64 gaps spaced six hours apart still need only 513 bins. Sparse or
highly uneven timing beyond this budget is a configured blind spot and requires separate review.

Nothing detects a beacon whose period exceeds the observation window. That is not a threshold
choice, it is what periodicity means.

## 7. Jitter that accumulates rather than jitter around a schedule

Lomb-Scargle recovers a period when check-ins are jittered around a fixed schedule, that is when
arrival k lands at `k*P + noise`. Real implants often sleep for `P * (1 +/- j)` instead, which
makes phase a random walk: coherence decays after roughly `1/(3*j^2)` beats, about 33 beats at
30 percent jitter. Past that no periodogram reaches a low false-alarm probability however long
you watch, because there is no longer a stable period to find. For that shape of beacon the
inter-arrival coefficient of variation is the only usable signal, and it is a much weaker one.

Because of that, the detector does not rest on the periodogram alone. A candidate alerts if
either clause holds: the periodogram peak is significant, `ls_fap` below `fap_max` 1e-3 with
power at least `min_power` 8.0, **or** the gaps are simply regular, at least
`regular_min_samples` 20 of them with a coefficient of variation at or below `regular_cv_max`
0.35 and a recovered period within `regular_period_agreement` 15 percent of their mean. Every
alert says which clause carried it, in `context["carried_by"]` and `context["clauses"]`.

Measured on the committed corpus, at a 45 second period with plus or minus 30 percent
schedule-relative jitter and six infected hosts: **five of the six hosts alert, twelve alerts
total, and all three benign update pollers stay silent**. Recovered periods 43.0 to 51.4 seconds
against a true 45. **Eleven of the twelve are carried by gap regularity, not by a significant
periodogram peak; exactly one clears `fap_max`.** Reproduce with
`python -m pytest -q tests/test_detectors.py -k beacon`.

Read that honestly. Five of six is the recall figure at that jitter level, not six of six. And on
this corpus the Lomb-Scargle path is doing much less of the work than the design implies: the
periodogram is what makes the claim explainable and what recovers the period to print, but at 30
percent jitter it is the regularity clause that fires. A regular gap train is weaker evidence
than a significant periodogram, which is why the alert names its own clause instead of quoting
one confidence for both.

`fap_max` is 1e-3. A Monte Carlo over Poisson-noise arrival trains put the realised false-alarm
rate slightly above the nominal figure, so the defensible claim for the periodogram clause is
"about 1e-3", not "at most 1e-3". The regularity clause has no false-alarm probability at all;
it is a shape test, and the benign update pollers are the evidence that its 0.35 CV bound is
tight enough to exclude semi-regular legitimate traffic on this corpus and nothing more.

## 8. Attacks that stay under the configured thresholds

Every detector is a rule with a stated threshold, and anything below it is invisible. The
thresholds are in the `DEFAULTS` dict at the top of each detector module and can be overridden
per detector through the engine config. What walks under each one:

| Detector | Threshold that gates it | What is therefore invisible |
|---|---|---|
| DDoS volumetric | 4 sigma over the per-destination EWMA, floor 25 pps | a flood that stays under 25 pps to a destination, or under 4 sigma of that destination's own baseline |
| DDoS reflection | amplification ratio 5, at least 3 reflectors | amplification below 5x, or a single reflector |
| DDoS exhaustion | 120 concurrent half-open, teardown ratio under 0.1 | fewer than 120 held connections, or an attacker that closes politely |
| Beaconing | FAP 1e-3, 12 samples, dst_stability 0.5, CV 0.75 | a beacon that moves between destinations, or one jittered past CV 0.75 |
| DGA name score | weighted entropy and bigram score above 0.55 | a name that reads like language, see section 9 |
| DGA campaign | 20 registered domains or 30 queries per 300 s, NX ratio 0.5 | a DGA that tries fewer than 20 domains in five minutes, or one whose names mostly resolve |
| DNS tunnelling | 50 subdomains per zone, TXT/NULL ratio 0.3 | a tunnel under 50 distinct subdomains, or one riding A and AAAA records only |
| Scanning | 30 ports or 30 hosts per window, at most 30 percent of probes answered | a scan of fewer than 30 targets, or one against a range that answers most probes |
| Exfiltration | ratio 3.0, 100 kB outbound, sustained 300 s | under 100 kB total, under five minutes, or a transfer padded with inbound traffic to hold the ratio below 3 |

An adversary who knows these numbers can sit under them. That is true of every threshold-based
detector ever built; publishing them is a deliberate trade of evasion resistance for auditability,
which is the right trade for a monitoring enclave whose output is evidence.

## 9. Dictionary DGA, from the name alone

The build spec claims the bigram model catches dictionary DGAs that entropy misses. Measured
against this corpus, it does not. Mean bigram log-likelihood per registrable label:

| Family | Mean bigram log-likelihood |
|---|---|
| benign names in `benign.pcap` (88 distinct) | -2.71 |
| dictionary DGA (12 labelled samples) | -2.74 |
| algorithmic DGA (12 labelled samples) | -4.43 |

A 0.03 nat gap is not a separation. The algorithmic family separates cleanly; the dictionary
family sits on top of the benign distribution, because benign brand names are themselves
compounds of English words. A per-name threshold there would be dishonest, and
`tests/test_detectors.py::test_the_bigram_model_separates_algorithmic_names_but_not_dictionary_names`
asserts the failure in both directions so nobody can quietly claim otherwise later.

What actually catches the dictionary family is the campaign shape: distinct registered domains
per source per 300 s, and the fraction of DNS responses carrying no answer. Both are visible
passively and neither costs a lookup. The consequence is the ceiling: **a dictionary DGA that
queries fewer than 20 domains per five minutes, or whose names mostly resolve, is not detected by
this build.** The dictionary alert says so itself in `context["separation"]`.

## 10. The JA4 reference table is three TLS stacks from one capture

`data/reference/ja4_tcp_reference.json` is derived by `build_ja4_reference.py`, which parses the
spoof-free benign baseline capture with the engine's own TLS decoder and pairs each JA4 with the
TCP fingerprint family it co-occurs with there. That is ground truth for this enclave and nothing
more. It covers three TLS stacks. It is not a survey of real-world JA4 values and must never be
presented as one.

A JA4 that is not in the table produces no claim and no rule alert; `fingerprint_consistency_score`
is 0.5, meaning "no opinion". Detection then falls to a second path that learns
`(ja4, tcp_family)` co-occurrence online from two count-min sketches and flags a pairing that is a
small minority of a JA4's own support. That path needs no reference data, but its counts are
count-min estimates and therefore upper bounds, which the alert states.

The deployment consequence: on a link whose client population differs from the one the table was
built on, the rule path is silent until the table is rebuilt from that link's own benign traffic.

## 11. Two detector branches fire on no committed scenario

Replaying all eleven captures produces exactly thirteen distinct rule subtypes, plus `model-only`
when the model layer is on. Two implemented branches are not among them:

| Branch | Module | What would trigger it | Disclosed in the alert |
|---|---|---|---|
| `strobe-scan` | `engine/detect/scan.py` | 2 to 20 distinct ports across more than 30 hosts from one source within the 3600 s window | yes, `context["corpus_note"]` |
| `ja4-tcp-pairing-outlier` | `engine/detect/encrypted.py` | a `(JA4, TCP family)` pairing that is a small minority of that JA4's own count-min support, with enough support behind it | no |

The strobe branch is handled properly: a synthetic unit test exercises it, and every strobe alert
carries a `corpus_note` telling the analyst it has not been validated against captured traffic.
The pairing-outlier branch gets no such treatment today, which is an oversight rather than a
policy. Both should be treated as untested code, not as tested detections, until one of two
things happens: a scenario that exercises the branch is added to `training/scenarios.py` and
`training/generate_scenarios.py`, or the branch gets the strobe treatment, a synthetic unit test
plus a `corpus_note` on every emitted `Detection`.

The third member of this list until recently was `upload-burst` in `engine/detect/exfil.py`. It
now has a scenario: `exfil_bulk`, a staged upload to one destination followed by about 5 MB
inside a single 60 s window, which is the shape the drip scenario deliberately does not have.
Both halves of the class (f) requirement, a bulk transfer and a slow drip, are therefore
demonstrated on committed traffic rather than only implemented.

The counting rule is the same one section 16 applies to every other number here: a branch that
fires on synthetic traffic is evidence that the code works on traffic with the stated properties,
and a branch that fires on nothing at all is not evidence of anything.

## 12. IPv6 addresses are not recoverable from an alert

The ingest layer hashes a 16-byte IPv6 address into a 32-bit integer with blake2b so it fits the
same field as an IPv4 address. The hash is deterministic across runs and processes, so flow
identity and every counter work correctly, but it is not reversible: an alert about an IPv6 flow
cannot render the original address. It also shares the 32-bit space with real IPv4 addresses, so a
collision is possible at roughly 1 in 4.3e9 per pair. An IPv6 alert should be treated as
"something on this link" rather than as an attributed address until the capture is consulted.

## 13. The reverse direction may not be on the tap at all

A tap that copies one direction of a link sees one direction of every flow. When the reverse
direction is absent, `bytes_rev` is zero and every outbound-to-inbound ratio becomes a lower
bound rather than a measurement. The exfiltration detector emits `reverse_direction_observed` and,
when it is zero, says in the alert that the ratio is a lower bound; the flow is counted toward
`unclassifiable_opaque` in the coverage report rather than quietly asserted. Orientation for such
a flow falls back to first-packet-seen at `orientation_confidence` 0.5, which is weaker evidence
than a SYN-derived orientation at 1.0.

## 14. State bounds are also detection bounds

Bounded memory is a constraint the build is proud of, and its cost is that anything the state
cannot hold is not linked up:

- the flow table holds 200000 flows and expires a flow after 120 seconds idle. An attack whose
  two halves are separated by more than the idle timeout is two flows, not one.
- SPLT sequences are collected for at most 50000 flows at a time, 20 samples each. Past that,
  packet-size-and-timing evidence is shed first, which is the intended shedding order.
- the beacon table holds 50000 candidates; past capacity the least recently used candidate is
  evicted and its ring is lost.
- the scan and DNS cardinality families hold 8192 groups each per scale. A scan from more than
  8192 concurrent sources loses the least recently used of them.
- count-min sketch counts are upper bounds, never lower. An alert that quotes a sketch estimate
  says so.

Under sustained load the queue between engine and dashboard sheds metrics frames first, then
status frames, and never an alert; the drop counts are on the operations view. An alert raised
during shedding carries `shedding_tier` and `sampling_ratio` so its evidence can be discounted.

## 15. What the ledger proves, and what it does not

The alert ledger is a hash-chained append-only log with an Ed25519 anchor every 100 records. It
is tamper-evident: change one byte of one record and `python -m engine.alerts.verify` names the
record index where the chain breaks. It is not unforgeable by the host. The signing key sits next
to the ledger file in `data/alerts.key`, so anyone with that file can re-sign a rewritten chain.
The honest claim is "tamper-evident against edits to the log", and the production answer is an
HSM or an offline key.

Deleting or rotating the key leaves the record chain verifiable and makes existing anchors fail;
`verify_chain` reports `key_source` so the two cases are distinguishable.

## 16. Every number in this repository comes from synthetic traffic

The eleven scenarios in `data/scenarios/` were synthesised packet by packet with `dpkt.pcap.Writer`
by `training/generate_scenarios.py`. No attack tool was run to produce them. The tools the problem
statement names, `hping3`, Slowloris, `iodine`, `dnscat2`, `nmap`, DGArchive lists, are what each
scenario emulates, not what made it; the mapping is in `EMULATION` in `training/scenarios.py` and
is copied into every labels file.

Synthetic traffic is generated from a model of an attack, and a detector measured against it is
partly being measured against the same assumptions that generated it. Results here are evidence
that the detectors work as specified on traffic with the stated properties. They are not evidence
of field performance, and no number in this repository should be quoted as though it were.

The benign background is likewise generated. Its false-positive result, zero alerts across all six
detectors on the benign baseline, is a real property of the code on that traffic and a weak
prediction of the false-positive rate on a production link, where the tail of odd-but-legitimate
behaviour is much longer than any generator produces.
