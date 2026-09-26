from __future__ import annotations

import math

import numpy as np
import pytest

from engine.analysis.lombscargle import (
    event_train,
    false_alarm_probability,
    lomb_scargle,
    peak_period,
    peak_period_from_iats,
)
from engine.state.beacon_table import BeaconTable
from engine.state.cms import CountMinSketch
from engine.state.entropy import EwmaDeviation, SlidingEntropy
from engine.state.flow_table import ENTRY_BYTES, SPLT_ENTRY_BYTES, SPLT_LEN, FlowTable
from engine.state.hll import HLLFamily, HyperLogLog
from engine.state.welford import Moments
from engine.types import ACK, SYN, TCP, UDP, PacketMeta

SEC = 1_000_000_000


def pkt(ts_s, src_ip, dst_ip, src_port=1234, dst_port=443, length=100, flags=0, proto=TCP, packets=1):
    return PacketMeta(
        ts_ns=int(ts_s * SEC),
        proto=proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        tcp_flags=flags,
        packets=packets,
    )


def test_flow_table_is_hard_capped():
    ft = FlowTable(capacity=500, idle_timeout_s=120)
    for i in range(500):
        ft.observe(pkt(i * 0.001, 0x0A000001, 0x0B000000 + i, src_port=1000 + i))
    at_capacity = ft.nbytes
    for i in range(500, 5000):
        ft.observe(pkt(i * 0.001, 0x0A000001, 0x0B000000 + i, src_port=1000 + i))
    assert len(ft) == 500
    assert ft.evicted == 4500
    assert ft.nbytes == at_capacity
    assert ft.nbytes <= ft.capacity_bytes


def test_flow_table_releases_splt_memory_on_expiry():
    ft = FlowTable(capacity=100, idle_timeout_s=10)
    for i in range(20):
        ft.observe(pkt(i * 0.01, 0x0A000001, 0x0A000002, 40000, 443, 100))
    assert ft.nbytes == ENTRY_BYTES + 20 * SPLT_ENTRY_BYTES
    ft.expire(int(60 * SEC))
    assert len(ft) == 0
    assert ft.nbytes == 0


def test_flow_table_sheds_splt_when_its_budget_is_spent():
    ft = FlowTable(capacity=200, splt_capacity=10)
    for i in range(200):
        for j in range(5):
            ft.observe(pkt(i + j * 0.01, 0x0A000001, 0x0B000000 + i, src_port=1000 + i))
    assert ft.splt_shed > 0
    assert ft.nbytes <= ft.capacity_bytes
    assert sum(len(f.splt) for f in ft) == ft.splt_capacity * SPLT_LEN


def test_flow_table_evicts_least_recently_used():
    ft = FlowTable(capacity=3)
    for i in range(3):
        ft.observe(pkt(i, 0x0A000001, 0x0B000000 + i, src_port=1000 + i))
    keep = pkt(3, 0x0A000001, 0x0B000000, src_port=1000)
    ft.observe(keep)
    ft.observe(pkt(4, 0x0A000001, 0x0B0000FF, src_port=1099))
    assert len(ft) == 3
    from engine.types import FlowKey

    assert FlowKey.of(keep)[0] in ft
    assert FlowKey.of(pkt(1, 0x0A000001, 0x0B000001, src_port=1001))[0] not in ft


def test_orientation_from_syn():
    ft = FlowTable(capacity=16)
    client, server = 0x0A000001, 0x0A000002
    st = ft.observe(pkt(0, client, server, 40000, 443, 60, SYN))
    assert st.orientation_confidence == 1.0
    assert st.initiator_ip == client and st.responder_port == 443
    ft.observe(pkt(0.01, server, client, 443, 40000, 1400, SYN | ACK))
    ft.observe(pkt(0.02, client, server, 40000, 443, 200, ACK))
    assert st.bytes_fwd == 260
    assert st.bytes_rev == 1400
    assert st.saw_syn and st.saw_synack


def test_orientation_from_synack_when_syn_missed():
    ft = FlowTable(capacity=16)
    client, server = 0x0A000001, 0x0A000002
    st = ft.observe(pkt(0, server, client, 443, 40000, 60, SYN | ACK))
    assert st.orientation_confidence == 1.0
    assert st.initiator_ip == client
    assert st.bytes_rev == 60


def test_orientation_fallback_flips_and_swaps_counters():
    ft = FlowTable(capacity=16)
    client, server = 0x0A000001, 0x0A000002
    st = ft.observe(pkt(0, server, client, 443, 40000, 500, ACK))
    assert st.orientation_confidence == 0.75
    assert st.initiator_ip == client and st.bytes_rev == 500
    ft.observe(pkt(1, client, server, 40000, 443, 60, SYN))
    assert st.orientation_confidence == 1.0
    assert st.initiator_ip == client
    assert st.bytes_fwd == 60 and st.bytes_rev == 500
    assert st.splt[0] == (-500, 0)


def test_a_service_port_names_the_responder_when_the_handshake_was_missed():
    client, server = 0x0A000001, 0x0A000002
    forward = FlowTable(capacity=16)
    st = forward.observe(pkt(0, client, server, 51000, 443, 1400, ACK))
    forward.observe(pkt(0.01, server, client, 443, 51000, 40, ACK))
    assert st.orientation_confidence == 0.75
    assert st.initiator_ip == client and st.initiator_port == 51000
    assert st.bytes_fwd == 1400 and st.bytes_rev == 40

    reverse = FlowTable(capacity=16)
    rt = reverse.observe(pkt(0, server, client, 443, 51000, 40, ACK))
    reverse.observe(pkt(0.01, client, server, 51000, 443, 1400, ACK))
    assert rt.orientation_confidence == 0.75
    assert rt.initiator_ip == client and rt.initiator_port == 51000
    assert rt.bytes_fwd == 1400 and rt.bytes_rev == 40


def test_two_ephemeral_ports_stay_at_the_lowest_orientation_confidence():
    ft = FlowTable(capacity=16)
    a, b = 0x0A000001, 0x0A000002
    st = ft.observe(pkt(0, a, b, 51000, 51001, 100, ACK))
    assert st.orientation_confidence == 0.5


def test_udp_orientation_uses_the_resolver_port_not_the_first_packet():
    ft = FlowTable(capacity=16)
    client, resolver = 0x0A000001, 0x08080808
    st = ft.observe(pkt(0, resolver, client, 53, 53000, 300, proto=UDP))
    assert st.orientation_confidence == 0.75
    ft.observe(pkt(0.01, client, resolver, 53000, 53, 80, proto=UDP))
    assert st.initiator_ip == client
    assert st.bytes_fwd == 80 and st.bytes_rev == 300
    assert st.flags_seen == 0


def test_evicted_flows_are_handed_back_before_they_are_dropped():
    seen = []
    ft = FlowTable(capacity=4, on_evict=seen.append)
    for i in range(10):
        ft.observe(pkt(i, 0x0A000001, 0x0A000100 + i, 40000 + i, 443, 100))
    assert len(ft) == 4
    assert ft.evicted == 6
    assert len(seen) == 6
    assert all(state.key not in ft for state in seen)


def test_flow_table_expires_idle_flows():
    ft = FlowTable(capacity=100, idle_timeout_s=10)
    ft.observe(pkt(0, 0x0A000001, 0x0A000002, 1000))
    ft.observe(pkt(5, 0x0A000001, 0x0A000003, 1001))
    ft.observe(pkt(30, 0x0A000001, 0x0A000004, 1002))
    gone = ft.expire(int(31 * SEC))
    assert len(gone) == 2
    assert len(ft) == 1
    assert ft.expired == 2


def test_cms_never_underestimates_and_stays_fixed_size():
    cms = CountMinSketch(width=2719, depth=5, seed=7)
    truth: dict[bytes, int] = {}
    rng = np.random.default_rng(1)
    for i in rng.integers(0, 4000, size=60_000):
        key = int(i).to_bytes(4, "big")
        truth[key] = truth.get(key, 0) + 1
        cms.add(key)
    before = cms.nbytes
    for key, count in truth.items():
        assert cms.estimate(key) >= count
    over = [cms.estimate(k) - v for k, v in truth.items()]
    assert np.mean(over) <= cms.error_bound
    assert cms.nbytes == before == 2719 * 5 * 4


def test_cms_linear_update_merges_by_sum():
    keys = [f"k{i}".encode() for i in range(500)]
    whole = CountMinSketch(width=512, depth=4, seed=3)
    part_a = CountMinSketch(width=512, depth=4, seed=3)
    part_b = CountMinSketch(width=512, depth=4, seed=3)
    rng = np.random.default_rng(2)
    for i in rng.integers(0, len(keys), size=20_000):
        key = keys[int(i)]
        whole.add(key)
        (part_a if i % 2 == 0 else part_b).add(key)
    part_a.merge(part_b)
    assert np.array_equal(part_a.table, whole.table)
    assert part_a.total == whole.total
    for key in keys:
        assert part_a.estimate(key) == whole.estimate(key)


def test_hll_is_accurate_and_fixed_size():
    h = HyperLogLog(m_bits=12, seed=0)
    n = 10_000
    for i in range(n):
        h.add(f"host-{i}".encode())
    est = h.count()
    assert abs(est - n) / n < 0.10
    assert h.nbytes == 4096


def test_hll_small_range_correction():
    h = HyperLogLog(m_bits=12)
    for i in range(200):
        h.add(f"s{i}".encode())
    assert abs(h.count() - 200) / 200 < 0.10
    assert HyperLogLog(m_bits=8).count() == 0.0


def test_hll_stays_finite_when_every_register_is_saturated():
    h = HyperLogLog(m_bits=12)
    h.registers[:] = 40
    estimate = h.count()
    assert estimate > 0.0
    assert math.isfinite(estimate)


def test_hll_does_not_bend_a_64_bit_estimate_with_a_32_bit_correction():
    h = HyperLogLog(m_bits=14, seed=3)
    n = 300_000
    for i in range(n):
        h.add(i.to_bytes(4, "big"))
    assert abs(h.count() - n) / n < 0.05


def test_hll_family_is_lru_bounded():
    fam = HLLFamily(m_bits=8, capacity=100)
    for g in range(5000):
        for k in range(20):
            fam.add(f"src{g}".encode(), f"dst{k}".encode())
    assert len(fam) == 100
    assert fam.nbytes <= fam.capacity_bytes
    assert abs(fam.count(b"src4999") - 20) / 20 < 0.30
    assert fam.count(b"src0") == 0.0


def test_sliding_entropy_rolls_forward():
    se = SlidingEntropy(window_s=1.0, buckets=20, slots=4096)
    for i in range(8):
        se.add(0, f"a{i}".encode())
    assert se.distinct(0) == 8
    assert se.entropy(0) == pytest.approx(1.0, abs=1e-9)
    for i in range(8):
        se.add(int(0.6 * SEC), f"b{i}".encode())
    assert se.distinct(int(0.6 * SEC)) == 16
    assert se.distinct(int(1.1 * SEC)) == 8
    assert se.distinct(int(5.0 * SEC)) == 0
    assert se.entropy(int(5.0 * SEC)) == 0.0


def test_sliding_entropy_collapses_on_a_single_source():
    se = SlidingEntropy(window_s=1.0, buckets=20, slots=4096)
    for i in range(500):
        se.add(int(i * 0.001 * SEC), b"one-source")
    assert se.entropy(int(0.5 * SEC)) == 0.0
    se2 = SlidingEntropy(window_s=1.0, buckets=20, slots=4096)
    for i in range(500):
        se2.add(int(i * 0.001 * SEC), f"spoof{i}".encode())
    assert se2.entropy(int(0.5 * SEC)) > 0.95
    assert se2.nbytes == se.nbytes


def test_ewma_deviation_flags_a_spike():
    e = EwmaDeviation(alpha=0.1, warmup=5)
    rng = np.random.default_rng(4)
    last = 0.0
    for _ in range(200):
        last = e.update(100.0 + rng.normal(0, 2.0))
    assert abs(last) < 4.0
    assert e.update(400.0) > 8.0


def test_welford_matches_numpy():
    rng = np.random.default_rng(11)
    xs = rng.gamma(2.0, 3.0, size=5000)
    m = Moments()
    for x in xs:
        m.add(float(x))
    mu = xs.mean()
    m2 = ((xs - mu) ** 2).mean()
    m3 = ((xs - mu) ** 3).mean()
    m4 = ((xs - mu) ** 4).mean()
    assert m.n == xs.size
    assert m.mean == pytest.approx(mu, rel=1e-10)
    assert m.std == pytest.approx(np.sqrt(m2), rel=1e-9)
    assert m.cv == pytest.approx(np.sqrt(m2) / mu, rel=1e-9)
    assert m.skew == pytest.approx(m3 / m2 ** 1.5, rel=1e-7)
    assert m.kurtosis == pytest.approx(m4 / (m2 * m2) - 3.0, rel=1e-6)


def _feed(bt, ft, src, dst, period_s, count, length, dport=8443, start=0.0):
    for i in range(count):
        p = pkt(start + i * period_s, src, dst, 50000, dport, length)
        bt.observe(p, ft.observe(p))


def test_beacon_prefilter_rejects_chatty_flows():
    bt = BeaconTable(capacity=100, ring=16, min_samples=4)
    ft = FlowTable(capacity=100)
    _feed(bt, ft, 0x0A000001, 0x0A000002, 0.01, 200, 200)
    assert len(bt) == 0
    assert bt.rejected == 200
    assert bt.nbytes == 0


def test_beacon_prefilter_rejects_bulk_transfers():
    bt = BeaconTable(capacity=100, ring=16, min_samples=4)
    ft = FlowTable(capacity=100)
    _feed(bt, ft, 0x0A000001, 0x0A000003, 30.0, 20, 1500)
    assert len(bt) == 0


def test_beacon_table_allocates_the_ring_lazily():
    bt = BeaconTable(capacity=100, ring=16, min_samples=4)
    ft = FlowTable(capacity=100)
    _feed(bt, ft, 0x0A000001, 0x0A000004, 45.0, 4, 300)
    assert len(bt) == 1 and bt.rings == 0
    _feed(bt, ft, 0x0A000001, 0x0A000004, 45.0, 1, 300, start=45.0 * 4)
    assert bt.rings == 1


def test_beacon_table_is_capped_and_reports_ready_candidates():
    bt = BeaconTable(capacity=64, ring=16, min_samples=4, recheck_s=0.0)
    ft = FlowTable(capacity=100_000)
    for d in range(400):
        _feed(bt, ft, 0x0A000001, 0x0B000000 + d, 45.0, 10, 300, dport=8000 + d)
    assert len(bt) == 64
    assert bt.evicted == 336
    assert bt.nbytes <= bt.capacity_bytes
    ready = bt.ready(int(500 * SEC))
    assert ready
    key, iats, stability = ready[0]
    assert len(key) == 4
    assert key[0] == TCP
    assert iats.size >= 4
    assert np.allclose(iats, 45.0, atol=1e-3)
    assert 0.0 < stability <= 1.0
    assert bt.ready(int(500 * SEC)) == []


def test_beacon_table_expires_on_its_own_ttl():
    bt = BeaconTable(capacity=100, ttl_s=3600, ring=16, min_samples=4)
    ft = FlowTable(capacity=100)
    _feed(bt, ft, 0x0A000001, 0x0A000005, 45.0, 8, 300)
    assert len(bt) == 1
    bt.ready(int(10_000 * SEC))
    assert len(bt) == 0 and bt.expired == 1 and bt.rings == 0


def _jittered_beacon(period, count, jitter, seed):
    rng = np.random.default_rng(seed)
    return np.sort(np.arange(count) * period + rng.uniform(-jitter, jitter, count) * period)


def test_lomb_scargle_resolves_a_jittered_beacon():
    period, faps = 45.0, []
    for seed in range(12):
        arrivals = _jittered_beacon(period, 64, 0.30, seed)
        recovered, power, fap = peak_period(arrivals)
        assert abs(recovered - period) / period < 0.10
        assert power > 0.0
        faps.append(fap)
    assert float(np.median(faps)) < 1e-3
    assert sum(f < 1e-3 for f in faps) >= 9


def test_lomb_scargle_gives_pure_noise_a_high_false_alarm_probability():
    for seed in range(12):
        rng = np.random.default_rng(1000 + seed)
        arrivals = np.cumsum(rng.exponential(45.0, 64))
        _, _, fap = peak_period(arrivals)
        assert fap > 1e-3


def test_false_alarm_probability_stays_exact_deep_in_the_tail():
    for power in (30.0, 35.0, 40.0, 60.0, 200.0):
        exact = -math.expm1(512 * math.log1p(-math.exp(-power)))
        got = false_alarm_probability(power, 512)
        assert got > 0.0, power
        assert abs(got - exact) / exact < 1e-9
    assert false_alarm_probability(0.0, 512) == 1.0
    assert false_alarm_probability(10.0, 512) > false_alarm_probability(12.0, 512)
    assert false_alarm_probability(2000.0, 512) == 0.0


def test_lomb_scargle_survives_missing_beats():
    rng = np.random.default_rng(21)
    arrivals = _jittered_beacon(45.0, 110, 0.15, 5)
    kept = arrivals[rng.random(arrivals.size) > 0.30]
    recovered, _, fap = peak_period(kept)
    assert abs(recovered - 45.0) / 45.0 < 0.10
    assert fap < 1e-3


def test_lomb_scargle_power_is_flat_for_a_constant_series():
    t = np.linspace(0.0, 100.0, 200)
    power = lomb_scargle(t, np.ones_like(t), np.linspace(0.01, 1.0, 32))
    assert np.all(power == 0.0)
    assert peak_period(np.array([1.0, 2.0])) == (0.0, 0.0, 1.0)


def test_event_train_preserves_every_arrival():
    arrivals = _jittered_beacon(45.0, 40, 0.2, 3)
    grid, counts = event_train(arrivals)
    assert counts.sum() == arrivals.size
    assert grid.size == counts.size


def test_beacon_samples_feed_the_periodogram():
    bt = BeaconTable(capacity=100, ring=64, min_samples=12, recheck_s=0.0)
    ft = FlowTable(capacity=100)
    rng = np.random.default_rng(6)
    t = 0.0
    for _ in range(70):
        t += 45.0 * (1.0 + rng.uniform(-0.05, 0.05))
        p = pkt(t, 0x0A000001, 0x0A000009, 50000, 8443, 320)
        bt.observe(p, ft.observe(p))
    ready = bt.ready(int(t * SEC))
    assert ready
    _, iats, _ = ready[0]
    assert iats.size == 64
    recovered, _, fap = peak_period_from_iats(iats)
    assert abs(recovered - 45.0) / 45.0 < 0.10
    assert fap < 1e-3
