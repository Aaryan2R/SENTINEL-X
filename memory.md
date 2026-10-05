# SENTINEL-X Project Memory

> Persistent project context for the team and AI coding agents.
> Read this first, then `rules.md`, `architecture.md`, `task.md`.
> Keep it short and current. Append to the log, edit the facts, delete what is no longer true.
> Do not store secrets, keys, credentials or personal data here.

---

## 1. Project snapshot

- **What:** SENTINEL-X is a passive, read-only network threat-detection system for networks monitored through one-way links (data diodes). It consumes packet/flow metadata and detects DDoS, SYN flood, UDP amplification, botnet C2, DGA, DNS tunnelling, encrypted-session anomalies, port scanning, reconnaissance and exfiltration.
- **Context:** hackathon prototype for an NTRO problem statement on AI-based threat detection over one-way traffic. The official wording has not been confirmed; check it against the problem statement list.
- **Pitch in one line:** "It proves it is passive, it measures its own blind spots, and every alert comes with evidence you can verify hasn't been tampered with."
- **Pillars:** provable passivity, diode-aware visibility, evidence-chained incidents. Supporting: evasion-aware detection (Red Team scorecard), bounded-memory streaming core, ATT&CK-mapped incidents.
- **Demo story:** start at "system normal" -> scan -> DGA -> C2 beacon -> SYN flood -> loss injected -> outbound attempt blocked -> tamper detected -> benchmark panel.

## 2. Current status

- Phase: **0 (setup)**. No application code written yet.
- Documents drafted (v1.0, for team review): PRD, Software Architecture and Design Document (arc42 format), Technology Stack Document.
- Context files created: `architecture.md`, `rules.md`, `task.md`, `memory.md`.
- Next: complete Phase 0 tasks (`task.md` T-001 to T-009), then the MVP slice.
- Team, owners, dependency-freeze date and demo date: **not set** (fill in).

## 3. Status log (append only, newest last)

| Date | Entry |
|------|-------|
| 2026-10-04 | Idea expanded; USP set (provable passivity, diode-aware visibility, evidence-chained incidents); PRD v1.0 and Design Document v1.0 drafted; reference design docs gathered. |
| 2026-10-05 | Tech Stack Document v1.0 drafted with versions checked against public release pages. Design Document corrected: Redis Stack is not needed (Redis 8 has Count-Min Sketch built in). Context files (`architecture.md`, `rules.md`, `task.md`, `memory.md`) created. |
| 2026-10-05 | T-001 done: repo layout initialised per architecture.md §14; .gitignore, .env.example, README; docs moved to docs/. |
| 2026-10-05 | T-002 done: uv project (Python 3.14), ruff+mypy+pytest configured, lockfile committed. All checks pass. |
| 2026-10-05 | T-003 done: React 19 + TS strict + Vite 8.3 + Tailwind 4 scaffold. Build clean. |
| 2026-10-05 | T-005 done: compose.yaml with core/demo profiles, enclave_net internal, all services hardened. Config validates. |
| 2026-10-05 | T-006 done: netns/tc/nftables scripts + orchestrators. Bash syntax valid. Needs Linux to run. |

## 4. Locked decisions (summary)

Full rationale: Design Document section 9. Change only via an ADR.

| ID | Decision | Why in one line |
|----|----------|-----------------|
| ADR-001 | Zeek as metadata source | Structured conn/dns/ssl/http logs; no parser writing |
| ADR-002 | Redis Streams bus (Kafka is the documented production path) | Simple, fast, hosts sketches |
| ADR-003 | Hybrid detection: rules/statistics + Isolation Forest + RF/XGBoost | Explainable and cheap; no opaque model |
| ADR-004 | Shard by src IP; second stream by dst IP | State stays local; DDoS needs dst aggregation |
| ADR-005 | Streaming sketches (HLL, Count-Min), EWMA/CUSUM | Bounded memory at high rates |
| ADR-006 | Noisy-OR fusion with within-group maximum | Transparent; avoids double counting |
| ADR-007 | SHAP for model signals; rule contributions for rules | Computed, defensible explanations |
| ADR-008 | Hash-chained evidence log with Merkle roots; no blockchain network | Tamper evidence at low cost |
| ADR-009 | One-way link emulated in software, proven by attestation, stated honestly | Credible without hardware |
| ADR-010 | Offline-only models/rules/intel via signed bundles | Nothing can be fetched from outside |
| ADR-011 | PostgreSQL for evidence; Redis for hot state | Right tool for each job |
| ADR-012 | Zeek in a no-network sensor; separate normaliser reads logs | Small, attestable passivity boundary |

## 5. Version baselines (checked 5 Oct 2026)

Re-check at dependency freeze. Lockfiles hold exact versions.

| Component | Baseline | Note |
|-----------|----------|------|
| Zeek | 9.0 LTS (released mid-Sept 2026); fallback 8.0.x LTS | 8.0.x keeps getting patches until 9.1 |
| JA4 package | `zeek/foxio/ja4` (0.18.x seen) | Plugin variant needs Zeek 7+; wider JA4+ under FoxIO License 1.1 |
| Redis | 8.8.x | HLL, Count-Min Sketch, Top-K, T-Digest built in; licence choice RSALv2/SSPLv1/AGPLv3 |
| Python | 3.14 (3.13 fallback) | 3.15 final on 1 Oct 2026, but scikit-learn 1.9 supports 3.11 to 3.14 |
| FastAPI | 0.141.x | Pre-1.0, frequent releases: pin exactly |
| scikit-learn | 1.9.x | |
| XGBoost | 3.4.x | |
| SHAP | 0.52.x | Keep additivity smoke test |
| PostgreSQL | 18.x (18.6 in Aug 2026) | PostgreSQL 19 expected autumn 2026: do not adopt during the build |
| React | 19.2.x | |
| Vite | 8.x | New bundler core: use plugins that declare Vite 8 support |
| Tailwind CSS | 4.x | |
| Recharts | 3.10.x | API differs from 2 |
| React Flow (`@xyflow/react`) | 12.x | Evidence graph |

## 6. Key facts and gotchas

**Design facts**
- Real data diodes are one-way: no ACKs, no retransmission, so loss is permanent. Visibility Health exists because of this.
- SPAN/mirror ports are bidirectional. Production needs a hardware diode or receive-only TAP; the demo emulates it (say so).
- Raw AF_PACKET sends bypass nftables output hooks, so the capture device also needs a `tc` egress drop.
- Live reputation lookups are impossible in a one-way enclave: use offline feeds or passive rarity against the local baseline.
- Count-based detectors under-count under loss (conservative); periodicity-based detectors are the most loss-sensitive (initial s_d for C2 is 0.6).
- Entropy alone misses wordlist-based DGAs: use n-gram models and NXDOMAIN rate. Low-and-slow scans need 1 h and 24 h windows. Jittered beacons need histogram/autocorrelation, not fixed variance.

**Engineering gotchas**
- Zeek capture on Windows is not practical; use Linux or a Linux VM. netns, tc and nftables need a real Linux kernel.
- joblib/pickle executes code on load: verify bundle signatures first; prefer native XGBoost JSON/UBJ.
- Install `zkg` packages at image build time; the runtime sensor has no network.
- `network_mode: none` containers have no interface until the setup script attaches one; health-check that the capture interface exists.
- Python hot path is the main throughput risk: batch, pipeline, vectorise, multi-process. Measure Zeek and Python stages separately.
- Zeek log JSON: enable `LogAscii::use_json` so fields parse by name.

**Licensing**
- Redis 8: choose a licence option deliberately if ever distributed or offered as a service; Valkey (BSD) is the alternative.
- FoxIO JA4+: only the TLS client fingerprint is claimed patent-free by FoxIO; other JA4+ methods are under FoxIO License 1.1. Enable only what is used.
- tcpreplay and Scapy are GPL (copyleft): demo tooling only.

## 7. Conventions (quick reference)

- Alert schema v1.0 (`architecture.md` section 6.3). Timestamps: ISO-8601 UTC with `Z`.
- Detectors: `name@semver`, calibrated scores in [0, 1], evidence and contributions mandatory.
- Correlation groups: `volume`, `periodicity`, `dns`, `tls`, `scan`.
- Severity: P >= 0.90 HIGH; 0.70 to 0.90 MEDIUM; 0.40 to 0.70 LOW; below 0.40 not alerted.
- Visibility: `VH = max(0, 1 - (0.4 L + 0.3 D + 0.2 G + 0.1 Q))`; adjusted confidence `conf * (1 - s_d * (1 - VH))`.
- Windows: 10 s, 5 min, 1 h, 24 h. Allowed lateness starts at 5 s.
- Evidence chain: SHA-256 over canonical JSON plus `prev_hash`; Merkle root per 100 records or 60 s.
- Initial weights and thresholds are starting values only; tune on labelled data, keep in versioned config.

## 8. Things we deliberately do not do

Active response of any kind; active scanning; payload inspection or decryption; antivirus; large deep-learning models or many ML algorithms; a real blockchain network; a 3D dashboard; claiming a hardware data diode when using emulation; publishing numbers we did not measure.

## 9. Evaluation plan (short)

- Datasets: CIC-IDS2017/2018 (known label issues in 2017: document handling), CTU-13, UNSW-NB15, public domain lists for DGA, plus own labelled traffic.
- Report: per-class precision/recall/F1, **false alerts per hour on benign traffic**, cross-dataset generalisation, p50/p95/p99 latency, sustained throughput with hardware stated, Red Team scorecard (including failures), behaviour at 1%, 5%, 10% packet loss.

## 10. Open questions

1. Official problem statement wording and judging criteria.
2. Expected input: PCAP, live mirror, or flow exports (NetFlow/IPFIX).
3. Required alert format beyond the JSON schema (for example STIX).
4. Target traffic rate and demo hardware.
5. Datasets provided or preferred by organisers.
6. Team size, owners, dependency-freeze date, demo date.
7. Is a physical receive-only demo link (for example a simple DIY diode) available? It would strengthen the passivity story.

## 11. References

- arc42 documentation: https://docs.arc42.org/home/ and https://github.com/arc42/arc42-template
- Security Onion architecture: https://soc.readthedocs.io/en/latest/architecture.html (hardware sizing: https://soc.readthedocs.io/en/latest/hardware.html)
- Zeek: https://zeek.org/get-zeek/ , install docs https://docs.zeek.org/en/current/install.html , JA4 in Zeek https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/
- RITA (beacon, DNS tunnelling detection over Zeek logs): https://www.activecountermeasures.com/?p=2934
- Kitsune (online NIDS, autoencoder ensemble): https://arxiv.org/pdf/1802.09089v1.pdf
- Tactical data diodes (GIAC): https://giac.org/paper/gicsp/242/tactical-data-diodes-industrial-automation-control-systems/142041
- Why SPAN is not acceptable for regulated networks (vendor): https://www.garlandtechnology.com/federal-data-diodes
- Data loss and retransmission in diodes: https://www.helpag.com/?p=34818
- Redis probabilistic structures: https://github.com/RedisBloom/redisbloom
- FoxIO JA4+ releases and licence: https://github.com/FoxIO-LLC/ja4/releases

## 12. How to maintain this file

- Append a row to the status log for every meaningful change (decision, milestone, discovered gotcha).
- When a fact becomes false, **edit or delete it**; do not leave stale statements.
- Move long explanations into ADRs or `docs/`; keep this file scannable.
- AI agents: update sections 2, 3, 6 and 10 when your work changes them, and say so in the PR description.
- Never record keys, passwords, tokens, personal data, or raw dataset contents here.
