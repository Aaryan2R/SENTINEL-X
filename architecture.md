# SENTINEL-X Architecture

> Passive, read-only network threat detection for one-way (data-diode) monitored networks.
> This file is the short, authoritative description of the system structure.
> Longer detail: `docs/` (PRD, Design Document, Tech Stack). Rules: `rules.md`. Work items: `task.md`.

---

## 1. Purpose

SENTINEL-X watches mirrored network traffic from inside a monitoring enclave that has **no path back** to the monitored network. It extracts metadata, runs several detectors, correlates weak signals into explainable incidents, and shows them on a live SOC dashboard.

Three differentiators drive the design:

1. **Provable passivity**: the sensor cannot transmit, and the system shows evidence of that live.
2. **Diode-aware visibility**: the system measures what it fails to see (loss, gaps, lag) and lowers confidence accordingly.
3. **Evidence-chained incidents**: every alert is explainable and stored in a tamper-evident hash chain.

## 2. Hard constraints (summary)

| ID | Constraint | Consequence |
|----|------------|-------------|
| TC-1 | No outbound packets from the sensor toward the monitored network | Capture interface has no address or route; egress dropped in layers |
| TC-2 | Metadata only: no payload decryption or storage | Features from headers, sizes, timing, DNS names, TLS handshake metadata |
| TC-3 | No internet at runtime | No live reputation lookups; models, rules and intel arrive as signed offline bundles |
| TC-4 | One commodity host (target 8 cores, 16 GB) | Scale by worker replicas; Kafka and multi-node are documented only |
| TC-5 | Linux containers via Docker Compose | netns, tc, nftables available for isolation |
| TC-6 | Open-source components; Python main language | See `docs/` tech stack |

Full rule set: `rules.md`.

## 3. System context

```
 Monitored network
        |  mirrored traffic
        v
 [ one-way link: data diode / receive-only TAP ]      (demo: software emulation)
        |  RX only
        v
 +-------------------- Monitoring enclave (no path back) --------------------+
 |  SENTINEL-X: sensor -> streams -> detectors -> correlation -> evidence    |
 |                                   |                                       |
 |                              REST + WebSocket -> SOC dashboard <- Analyst |
 +----------------------------------------------------------------------------+
        ^
        | signed bundles (models, rules, intel) via controlled offline media
```

## 4. Pipeline

```
Capture/replay (RX only)
   -> Zeek (conn, dns, ssl, http, capture_loss, stats logs)
   -> Normaliser (internal flow schema + sequence numbers)
   -> Redis Streams (sharded by src IP; second stream by dst IP)
   -> Detection workers (rules + sketches | behavioural ML | threat detectors)
   -> Correlator (group signals, fuse risk, visibility modifier, SHAP/rule explanations)
   -> Incident engine (ATT&CK, kill-chain stage, timeline)
   -> Evidence writer (hash chain) -> PostgreSQL
   -> FastAPI (REST + WebSocket) -> React SOC dashboard

Side channels:  Visibility monitor (drops, gaps, lag -> confidence modifiers)
                Passivity monitor (TX counters, tc/nft state -> attestation)
```

## 5. Components

| # | Component | Responsibility | Tech |
|---|-----------|----------------|------|
| 1 | Capture / replay | Receive-only capture or PCAP replay; never transmits | libpcap via Zeek; tcpreplay (demo) |
| 2 | Sensor | Protocol analysis; writes JSON logs to a volume; **no network** | Zeek, JA4/JA3 packages |
| 3 | Normaliser | Parse logs, map to flow schema, stamp `seq`, publish to streams | Python |
| 4 | Stream bus | Partitioned streams, consumer groups, bounded length | Redis 8 Streams |
| 5 | Detection workers | Per-entity state, detectors, calibrated signals | Python, NumPy, sklearn, XGBoost |
| 6 | Correlator | Grouping, fusion, modifier, explanation, dedupe | Python, SHAP |
| 7 | Incident engine | Incidents, ATT&CK, kill chain, timeline | Python |
| 8 | Evidence writer | Single-writer hash chain and Merkle roots | Python, PostgreSQL |
| 9 | Visibility monitor | Visibility Health, shedding state | Python |
| 10 | Passivity monitor | Attestation, lab-only outbound self-test | Python, tc, nftables |
| 11 | API | REST and WebSocket | FastAPI |
| 12 | Dashboard | SOC views, alert detail, "Why was I alerted?", attestation, benchmark | React, TypeScript |
| 13 | Replay / generator / bench | Seeded labelled traffic, benchmark harness | tcpreplay, Scapy, scripts |
| 14 | Bundle manager | Verify and activate signed bundles | Python, Ed25519 |

## 6. Data contracts

### 6.1 Normalised flow record (stream payload)

| Field | Notes |
|-------|-------|
| `sensor_id`, `seq` | Per-sensor monotonic sequence; used for gap detection |
| `ts_start`, `ts_end` | Event time (UTC seconds, float) |
| `uid` | Zeek connection ID |
| `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto` | Five-tuple |
| `service`, `conn_state`, `history` | From Zeek conn log; `conn_state` feeds failed-connection ratio |
| `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts` | Volume and symmetry |
| `dns_query`, `dns_qtype`, `dns_rcode` | DNS events |
| `tls_ja3`, `tls_ja4`, `tls_sni`, `tls_version` | TLS sessions when available |

### 6.2 Detector interface

```python
class Detector(Protocol):
    name: str
    version: str
    loss_sensitivity: float                 # s_d in [0, 1]

    def update(self, flow: Flow, state: EntityState) -> None: ...
    def evaluate(self, entity: str, now: float) -> list[Signal]: ...

@dataclass
class Signal:
    entity: str            # e.g. source IP
    threat_class: str      # e.g. C2_BEACONING
    score: float           # calibrated 0..1
    group: str             # volume | periodicity | dns | tls | scan
    evidence: dict
    contributions: list    # [(signal_name, value), ...]
    window: tuple          # (start_ts, end_ts)
    detector: str          # name@version
```

### 6.3 Alert schema (v1.0)

Fields: `schema_version`, `alert_id`, `incident_id`, `timestamp` (ISO-8601 UTC), `flow_id`, `source_ip`, `destination_ip`, `destination_port`, `threat_class`, `attack_technique`, `kill_chain_stage`, `severity`, `confidence`, `visibility_health`, `evidence{}`, `explanation[{signal, contribution}]`, `detector_version`, `evidence_hash`, `prev_hash`.

Contributions come from SHAP (tree models) or rule weights, never hand-set.

## 7. Streaming and state

- **Sharding:** primary stream by `hash(src_ip)`; each worker owns all state for its sources (no locks). Many-to-one attacks (DDoS) use a second stream sharded by `dst_ip`.
- **Sketches:** HyperLogLog for unique ports and hosts (mergeable across time buckets), Count-Min Sketch for destination heavy hitters, EWMA with CUSUM for rate shifts. Memory per entity is constant.
- **Windows:** 1 s buckets roll into 10 s, 5 min, 1 h, 24 h windows by merging sketches. Long windows catch low-and-slow behaviour.
- **Time:** event time from the flow record; small allowed lateness (start at 5 s); late events counted in the current bucket and flagged.
- **Back-pressure:** bounded streams (approximate trim); consumer lag feeds the shedding controller.
- **Shedding order:** ML scoring first, then secondary detectors. Every shed action is recorded and lowers Visibility Health. Never drop silently.
- **Dead letter:** malformed input goes to `dead:flows` with a counter; the pipeline never stops on bad input.

## 8. Detection engine

| Threat | Key features | Method | ATT&CK | Group | s_d (initial) |
|--------|--------------|--------|--------|-------|---------------|
| DDoS / volumetric | pkts/s, bytes/s, unique sources, source entropy, destination concentration | EWMA/CUSUM + rules | T1498 | volume | 0.3 |
| SYN flood | SYN rate, SYN:ACK ratio, incomplete handshakes | Rules + ratios | T1498.001 | volume | 0.3 |
| UDP amplification | response/request bytes, asymmetry, amplification ports | Rules + RF | T1498.002 | volume | 0.3 |
| Port scan / recon | unique dst ports/hosts (HLL), failed ratio, fan-out | Multi-window rules | T1046, T1018 | scan | 0.3 |
| Botnet C2 | inter-arrival periodicity, destination repetition, size symmetry | Histogram/autocorrelation + RF | T1071, T1573 | periodicity | 0.6 |
| DGA | length, entropy, digit ratio, n-grams, NXDOMAIN rate | n-gram model + XGBoost | T1568.002 | dns | 0.4 |
| DNS tunnelling | query length, subdomain entropy, unique subdomains, TXT use | Rules + cumulative counters | T1071.004 | dns | 0.4 |
| Encrypted malware | JA3/JA4, packet sizes/timing, direction, bursts | XGBoost + fingerprint rarity | T1573 | tls | 0.5 |
| Exfiltration | outbound bytes, in/out ratio, new destinations | Baseline + Isolation Forest | T1041, T1048 | volume | 0.3 |

All numeric parameters are initial values: tune on labelled data and keep them in versioned config.

## 9. Correlation, scoring, explainability

- Each detector emits a **calibrated** score in [0, 1].
- Signals are grouped (volume, periodicity, dns, tls, scan). Within a group take the **maximum** so one behaviour is not double counted.
- Incident risk: `P = 1 - product over groups g of (1 - max score in g)`, then apply the visibility modifier.
- Visibility: `VH = max(0, 1 - (0.4 L + 0.3 D + 0.2 G + 0.1 Q))` with L capture loss, D interface drops, G sequence gaps, Q queue lag (each normalised to [0, 1]). Adjusted confidence: `conf * (1 - s_d * (1 - VH))`.
- Severity: P >= 0.90 HIGH; 0.70 to 0.90 MEDIUM; 0.40 to 0.70 LOW; below 0.40 informational (not alerted). Raise one level for configured critical assets.
- Explanations: SHAP TreeExplainer for RF/XGBoost; rule contributions for deterministic detectors; group marginal contribution (`P - P without g`) at incident level. SHAP runs asynchronously and never blocks the hot path.
- Deduplicate by `(entity, threat_class, window)`; update last-seen instead of re-alerting.

## 10. Trust subsystem

### 10.1 Passivity (layers)

1. **No identity:** capture interface has no IPv4/IPv6 address; ARP and IPv6 off; no routes.
2. **Device-level egress drop:** `tc` clsact egress `matchall` drop (covers raw AF_PACKET sends that bypass nftables output hooks).
3. **Netfilter:** nftables output chain with policy drop.
4. **Least privilege:** sensor drops all capabilities except capture, read-only root, no network other than the capture interface.
5. **Evidence:** monitor publishes TX counters (expected 0), tc drop counters, nft policy hash, capabilities, open sockets.
6. **Honest limit:** this is a software emulation. Production guarantee is a hardware data diode or receive-only TAP. SPAN/mirror ports are bidirectional and are not a substitute.

The outbound self-test is **lab mode only** (disabled by default).

### 10.2 Evidence integrity

- Single writer. `hash = SHA-256(canonical JSON of record without hash fields || prev_hash)`.
- Merkle root every 100 records or 60 s; optional Ed25519 signature on roots (key kept outside the sensor).
- Verification recomputes the chain and reports the first inconsistent record.
- This is tamper evidence and chain of custody. It is not a distributed ledger.

### 10.3 Offline bundles

Signed (Ed25519) archives for models, rules and intelligence. Verify signature and hashes **before** loading anything (joblib pickles execute code on load). Keep the previous version for rollback. Record the import in the evidence chain.

## 11. Deployment

Single host, Docker Compose, profiles `core` and `demo`.

| Service | Network | Notes |
|---------|---------|-------|
| replayer (demo only) | writes to capture veth peer | tcpreplay or generator |
| sensor | own netns, capture interface only, no IP | Zeek only; CAP_NET_RAW; read-only; logs to a volume |
| normaliser | `enclave_net` | reads Zeek log volume read-only |
| redis | `enclave_net` | Streams, HLL, CMS (built in to Redis 8) |
| detector xN | `enclave_net` | scaled replicas; each owns shards |
| correlator, evidence-writer | `enclave_net` | single instance each; evidence writer is single-writer |
| postgres | `enclave_net` | alerts, incidents, hash chain, health samples |
| api, frontend | `enclave_net`; frontend also on `ui_net` | FastAPI; nginx + React; port bound to enclave-facing address |
| monitor | `enclave_net` + read access to sensor interface stats | visibility + passivity |

`enclave_net` is a Docker `internal: true` network (no external route).

Demo vs production: software emulation vs hardware diode/TAP; PCAP replay vs mirrored traffic; one host vs Kafka + multiple nodes.

## 12. Key runtime scenarios

1. **Steady state:** frames -> Zeek logs -> normaliser -> streams -> detectors -> correlator -> incident -> evidence -> API -> dashboard.
2. **C2 becomes an incident:** periodicity (C2), DGA (dns), rare JA4 (tls) for one host -> max per group -> noisy-OR -> one incident with timeline.
3. **Degraded visibility:** loss injected -> VH drops -> per-detector modifiers -> lower confidence and a dashboard note.
4. **Tamper demo:** edit a stored record -> verify chain -> fails at that record.
5. **Replay:** choose scenario, duration, rate -> seeded replayer -> same pipeline -> benchmark recorded.
6. **Bundle import:** verify signature -> activate -> log in chain; rollback available.

## 13. Architecture decisions (index)

| ID | Decision |
|----|----------|
| ADR-001 | Zeek as metadata source |
| ADR-002 | Redis Streams as bus (Kafka is the documented production path) |
| ADR-003 | Hybrid detection: rules/statistics + Isolation Forest + RF/XGBoost |
| ADR-004 | Shard by src IP, second stream by dst IP |
| ADR-005 | Streaming sketches for per-entity state |
| ADR-006 | Noisy-OR fusion with within-group maximum |
| ADR-007 | SHAP for model signals, rule contributions for rules |
| ADR-008 | Hash-chained evidence log; no blockchain network |
| ADR-009 | Emulate the one-way link in software; prove it; state it honestly |
| ADR-010 | Offline-only models/rules/intel via signed bundles |
| ADR-011 | PostgreSQL for evidence; Redis for hot state |
| ADR-012 | Zeek in a no-network sensor; separate normaliser reads its logs |

Rationale and alternatives: Design Document, section 9.

## 14. Repository map

```
sentinel-x/
  compose.yaml                 # profiles: core, demo
  infra/   netns/  nftables/  tc/
  sensor/  Dockerfile  zeek/local.zeek  zeek/packages.txt
  engine/  pyproject.toml  uv.lock
           sentinel/  common/ normaliser/ detector/ correlator/ evidence/ monitor/ bundles/
                      detectors/  (c2, dga, dns_tunnel, scan, ddos, syn, udp_amp, tls, exfil)
                      features/   (shared by training and inference)
           models/  tests/
  api/        # FastAPI
  frontend/   # React + TypeScript + Vite
  traffic/    generator/ scenarios/ replay/
  bench/      # benchmark harness and report templates
  docs/       # PRD, design document, tech stack, ADRs
```

## 15. How to add a detector

1. Create `engine/sentinel/detectors/<name>.py` implementing the `Detector` protocol.
2. Declare `name`, `version` (semver), `loss_sensitivity`, correlation `group`, ATT&CK technique.
3. Keep state in sketches or bounded windows only. No unbounded sets or lists per entity.
4. Emit calibrated scores with evidence and contributions.
5. Add a labelled scenario in `traffic/scenarios/` and an evasive variant for the Red Team set.
6. Add unit tests, a seeded regression test, and a no-alert-on-benign test.
7. Register the detector and its parameters in versioned config.
8. Update this file (section 8), the PRD matrix, and `memory.md`.
