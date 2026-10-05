# SENTINEL-X Task Plan

> Phased work breakdown derived from the PRD delivery plan (section 15).
> Update status here in the same PR as the work. Rules: `rules.md`. Structure: `architecture.md`.

**Legend**
- Status: `[ ]` todo, `[~]` in progress, `[x]` done, `[!]` blocked
- Size: **S** (about half a day or less), **M** (1 to 2 days), **L** (3 days or more). Sizes are rough planning guesses, not commitments.
- Priority: **P0** required for the MVP demo, **P1** important, **P2** stretch
- `FR-xx` refers to PRD functional requirements. `Dep:` lists task IDs that must be done first.

**Current focus:** Phase 0 (setup). No code has been written yet.

**Owners and dates:** assign owners and fill target dates when the team schedule is known (`Owner: ___`, `Target: ___`).

---

## Phase 0: Setup and hello-flow

Goal: the services start and one replayed flow reaches the dashboard.

- [x] **T-001** Initialise repository layout (see `architecture.md` section 14), `.gitignore`, `.env.example`, `README` quickstart. P0, S
- [x] **T-002** Python tooling: `uv` project, `ruff`, `mypy`, `pytest`, pre-commit hooks, committed lockfile. P0, S. Dep: T-001
- [x] **T-003** Frontend tooling: React 19 + TypeScript + Vite 8 + Tailwind 4 skeleton, lint, `npm ci` lockfile. P0, S. Dep: T-001
- [ ] **T-004** Sensor image: Zeek (pinned by digest; 9.0 LTS, 8.0.x fallback), install JA4 package with `zkg` at build time, JSON logs enabled. P0, M. Dep: T-001
- [x] **T-005** Compose skeleton with profiles `core` and `demo`; `enclave_net` as `internal: true`; services as stubs. P0, M. Dep: T-001
- [ ] **T-006** Namespace setup scripts in `infra/` (veth pair, no IP, ARP/IPv6 off, tc egress drop, nftables output drop) with teardown. P0, M. Dep: T-001
- [ ] **T-007** Traffic generator v1 and seeded replay: normal traffic plus one scan scenario, labelled. P0, M. Dep: T-001
- [ ] **T-008** Hello-flow: PCAP replay -> Zeek -> normaliser (minimal) -> Redis stream -> API -> dashboard shows one flow. P0, M. Dep: T-004, T-005, T-006, T-007
- [ ] **T-009** CI pipeline: lint, type check, unit tests, seeded regression stub, TX = 0 assertion stub. P0, M. Dep: T-002, T-003

**Exit criteria:** `docker compose --profile demo up` runs; replay produces a visible flow; CI is green.

---

## Phase 1: Core pipeline

Goal: scan, DDoS, SYN flood and DGA detection with explained alerts on a live dashboard.

### Ingestion and streaming
- [ ] **T-010** Define Pydantic schemas: flow, signal, alert (schema v1.0). FR-40. P0, S. Dep: T-002
- [ ] **T-011** Normaliser: parse Zeek JSON logs (conn, dns, ssl), map to flow schema, add `seq` and event time, publish to src and dst streams. FR-01, FR-03. P0, M. Dep: T-010, T-008
- [ ] **T-012** Stream layer: bounded streams, consumer groups, shard assignment, dead-letter stream and counters. FR-03. P0, M. Dep: T-011
- [ ] **T-013** Bus interface abstraction so Redis can be swapped later (ARC-6). P0, S. Dep: T-012
- [ ] **T-014** No-outbound proof: check TX counters stay 0 during pipeline tests. FR-04. P0, S. Dep: T-006, T-009

### Detection framework
- [ ] **T-015** Detector protocol, `Signal`, detector registry, versioned config loader. P0, M. Dep: T-010
- [ ] **T-016** Sketch toolkit: HyperLogLog wrapper (bucketed, mergeable), Count-Min Sketch wrapper, EWMA/CUSUM with property tests. P0, L. Dep: T-015
- [ ] **T-017** Window aggregator: 1 s buckets rolled into 10 s, 5 min, 1 h, 24 h; event-time with allowed lateness. P0, L. Dep: T-016
- [ ] **T-018** Detection worker runtime: multi-process, batch reads, shard ownership, per-entity error isolation. P0, L. Dep: T-012, T-015

### Detectors (first set)
- [ ] **T-019** Port scan / recon detector (vertical, horizontal, mixed; low-and-slow via long window) plus scenario, evasive variant, tests. FR-13. P0, L. Dep: T-017, T-018
- [ ] **T-020** Volumetric DDoS detector (rates, unique sources, source entropy, destination concentration; second dst-keyed stream). FR-10. P0, L. Dep: T-017, T-018
- [ ] **T-021** SYN flood detector (SYN rate, SYN:ACK ratio, incomplete handshakes). FR-11. P0, M. Dep: T-017, T-018
- [ ] **T-022** DGA feature extractor and n-gram model trained offline on benign domains; XGBoost classifier; scenario and tests. FR-14. P0, L. Dep: T-018

### Alerting, API and UI
- [ ] **T-023** Correlator v0: dedupe by `(entity, threat_class, window)`, severity mapping, alert emission. P0, M. Dep: T-018
- [ ] **T-024** PostgreSQL schema and Alembic migrations (alerts, incidents, samples). P0, M. Dep: T-010
- [ ] **T-025** API: alerts, alert detail, stats summary, WebSocket live stream. FR-41. P0, M. Dep: T-023, T-024
- [ ] **T-026** Dashboard v0: live traffic, active alerts, threat-type counts, top sources, alert detail view with evidence. FR-42, FR-43. P0, L. Dep: T-025, T-003

**Exit criteria:** replay shows scan and flood alerts with evidence within the latency target; benign scenario produces no alerts.

---

## Phase 2: Trust features

Goal: passivity and visibility are measurable and visible in the UI.

- [ ] **T-030** Passivity monitor: read TX counters, tc drop stats, nftables policy hash, capabilities, open sockets; store samples. FR-30. P0, M. Dep: T-006
- [ ] **T-031** Attestation panel in the dashboard (live values from the host, not static text). FR-30. P0, M. Dep: T-030, T-026
- [ ] **T-032** Lab-only outbound self-test (disabled by default; result recorded). FR-31. P1, M. Dep: T-030
- [ ] **T-033** Zeek capture-loss and stats log parsing; interface drop and sequence gap tracking; queue lag. FR-32. P0, M. Dep: T-011
- [ ] **T-034** Visibility Health computation and per-detector modifiers (`conf * (1 - s_d * (1 - VH))`). FR-32. P0, M. Dep: T-033, T-023
- [ ] **T-035** Shedding controller: disable ML then secondary detectors under lag; record every shed action; reflect in VH. P0, M. Dep: T-034, T-018
- [ ] **T-036** Loss-injection tooling in the replayer (1%, 5%, 10%) and regression tests. P0, M. Dep: T-007, T-034
- [ ] **T-037** Health strip in the dashboard (VH, shedding, passivity) on the main screen. P0, S. Dep: T-031, T-034

**Exit criteria:** TX = 0 visible live; injected loss lowers VH and alert confidence on screen.

---

## Phase 3: Intelligence

Goal: C2 detection, behavioural ML, incidents with explanations.

- [ ] **T-040** C2 beaconing detector: dominant-period fraction, autocorrelation peak, size consistency; jitter-robust; scenario and Red Team variants. FR-16. P0, L. Dep: T-017, T-018
- [ ] **T-041** Shared feature module for training and inference (ARC-7). P0, M. Dep: T-010
- [ ] **T-042** Offline training pipeline: datasets loader, Isolation Forest, Random Forest/XGBoost, calibration, model artefact format (native XGBoost, no unsigned pickles). FR-19. P0, L. Dep: T-041
- [ ] **T-043** Behavioural ML scorer in workers (versioned models, calibrated scores). FR-19. P0, M. Dep: T-042, T-018
- [ ] **T-044** Signal grouping and fusion (group max, noisy-OR, visibility modifier) with unit tests. FR-21. P0, M. Dep: T-023, T-034
- [ ] **T-045** Explainer: SHAP (async, above threshold), rule contributions, group marginal contributions; additivity smoke test. FR-22. P0, L. Dep: T-043, T-044
- [ ] **T-046** Incident engine: per-entity incidents, kill-chain stage, ATT&CK mapping. FR-20. P0, L. Dep: T-044
- [ ] **T-047** Timeline view and API (per source, progression stages). FR-24. P1, M. Dep: T-046, T-026
- [ ] **T-048** "Why was I alerted?" view with contributions. FR-22. P0, M. Dep: T-045, T-026
- [ ] **T-049** Evidence graph view (React Flow). FR-23. P1, M. Dep: T-046, T-026
- [ ] **T-050** DNS tunnelling detector (cumulative unique subdomains per parent domain, entropy, TXT use). FR-15. P1, L. Dep: T-017, T-018
- [ ] **T-051** UDP amplification detector. FR-12. P1, M. Dep: T-017, T-018

**Exit criteria:** a scripted multi-stage scenario yields one explained incident; explanations are computed, not hand-set.

---

## Phase 4: Hardening and proof

Goal: tamper evidence, evasion scorecard, benchmark and a rehearsed demo.

- [ ] **T-060** Evidence writer: single writer, canonical JSON, `prev_hash`, advisory lock, Merkle roots. FR-33. P1, L. Dep: T-024, T-023
- [ ] **T-061** Verification routine and CLI/API, plus the tamper demo (edit a record, verification fails at that record). FR-33. P1, M. Dep: T-060
- [ ] **T-062** Replay UI: choose scenario, duration, rate; seeded and deterministic; no external network. FR-50. P0, L. Dep: T-007, T-025
- [ ] **T-063** Traffic generator v2: every in-scope attack class, labelled; scenario library. FR-51. P0, L. Dep: T-007
- [ ] **T-064** Red Team mode: evasive variants (jittered beacons, low-and-slow scan, wordlist DGA, slow tunnelling) and detection-rate scorecard. FR-52. P1, L. Dep: T-063, T-040, T-019, T-022, T-050
- [ ] **T-065** Benchmark harness: throughput and p50/p95/p99 latency, memory soak, hardware details, report template. FR-53. P0, L. Dep: T-018, T-062
- [ ] **T-066** Benchmark panel in the dashboard (measured values only). FR-53. P0, S. Dep: T-065
- [ ] **T-067** Encrypted-session detector (JA4/JA3, sizes, timing, direction, bursts); UI note "payload encrypted: metadata-only inspection". FR-17. P1, L. Dep: T-042
- [ ] **T-068** Exfiltration detector (baseline and peer-group volume, in/out ratio). FR-18. P1, L. Dep: T-042
- [ ] **T-069** Bundle manager: Ed25519 verification, activation, rollback, evidence entry. FR-34. P2, L. Dep: T-060
- [ ] **T-070** Evaluation run: per-class precision/recall, false alerts per hour on benign, cross-dataset test. P0, L. Dep: T-042
- [ ] **T-071** Performance tuning pass based on benchmark (batching, shards, worker count). P0, L. Dep: T-065
- [ ] **T-072** Offline delivery: `docker save` bundle, checksums, import instructions, clean-machine install test. P0, M. Dep: T-005
- [ ] **T-073** Demo script and rehearsal (timeline in PRD section 13); record a fallback run. P0, M. Dep: T-062, T-061
- [ ] **T-074** Finalise docs: update PRD/design/tech stack with measured results, publish benchmark report. P0, M. Dep: T-065, T-070

**Exit criteria:** benchmark report with measured numbers; Red Team scorecard published (including failures); demo runs from one command with no internet.

---

## Cross-cutting (continuous)

- [ ] **T-080** Keep seeded regression suite current as detectors change (TST-2).
- [ ] **T-081** Keep `architecture.md`, `memory.md` and ADRs current (DOC-1, DOC-2).
- [ ] **T-082** Dependency freeze on [date]: stop upgrades, security fixes only (DEP-4).
- [ ] **T-083** Licence review before any redistribution (Redis 8 licence choice, FoxIO JA4+ terms, GPL demo tools).
- [ ] **T-084** Threshold and weight tuning from labelled data; record parameters in versioned config.

---

## Suggested critical path

`T-001 -> T-004/T-005/T-006/T-007 -> T-008 -> T-011 -> T-012 -> T-015/T-016 -> T-017 -> T-018 -> T-019/T-020/T-021 -> T-023 -> T-025 -> T-026` (MVP slice), then `T-033 -> T-034` (visibility), `T-040`, `T-044 -> T-046`, `T-062`, `T-065`.

## MVP slice (if time is short)

Keep: Phase 0, Phase 1, T-030/T-031, T-033/T-034/T-037, T-040, T-044, T-046, T-062, T-063, T-065, T-066, T-073.
Defer first: T-067, T-068, T-069, T-049, T-051, T-050, T-047.
Never defer: passivity evidence (T-030/T-031) and the measured benchmark (T-065).

## Risks to watch while executing

- Python hot path cannot meet the flow-rate target -> measure early (T-065 can start as soon as T-018 works).
- Zeek 9.0 or the JA4 package not ready in your environment -> keep the 8.0.x fallback image.
- Namespace and tc setup differs on the demo host -> test T-006 on the actual demo machine early.
- Scope creep -> P0 first; stretch items only after the demo path works.

## Open questions (carry into planning)

1. Exact official problem statement wording and evaluation criteria.
2. Input judges expect: PCAP files, mirrored live traffic, or flow exports.
3. Required alert format beyond the JSON schema (for example STIX).
4. Traffic rate to demonstrate and the hardware of the demo machine.
5. Datasets provided or preferred by the organisers.
6. Team size, owners and the dependency-freeze and demo dates.
