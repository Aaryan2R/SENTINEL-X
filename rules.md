# SENTINEL-X Project Rules

> Rules for everyone who changes this repository: team members and AI coding agents.
> Priority when rules conflict: **Invariants > Security > Correctness > Honesty > Style**.
> Keywords: **MUST**, **MUST NOT**, **SHOULD** are used in their usual sense.
> Reference rules by ID in commits and PRs (for example: "complies with INV-1, DET-3").

---

## 1. Invariants (never break these)

| ID | Rule |
|----|------|
| INV-1 | The sensor MUST NOT transmit anything toward the monitored network. No probes, handshakes, DNS lookups, pings, or API calls. |
| INV-2 | No code path MAY perform active response: no blocking, rate limiting, IP banning, firewall changes, or scanning. |
| INV-3 | The system MUST NOT decrypt traffic or store packet payloads. Metadata only. |
| INV-4 | No component MAY make outbound network calls at runtime (no internet, no cloud APIs, no telemetry, no package downloads, no model downloads). |
| INV-5 | The sensor container MUST run with no network other than the capture interface, a read-only root filesystem, and only the capabilities capture needs. |
| INV-6 | Evidence records are append-only. Nothing MAY update or delete a stored evidence record. |
| INV-7 | Models, rules and intel MUST NOT be loaded unless their bundle signature and hashes have been verified first. |
| INV-8 | Published numbers (throughput, latency, accuracy) MUST come from the benchmark and evaluation harness. Never estimate or invent them. |

If a task seems to require breaking an invariant, **stop and ask**. Do not work around it.

## 2. Security rules

- SEC-1: MUST NOT load pickle/joblib files from any unverified source. Prefer native formats (XGBoost JSON/UBJ). Unpickling runs code.
- SEC-2: Cryptography MUST use the `cryptography` package (Ed25519) and `hashlib` (SHA-256). No custom crypto.
- SEC-3: Private signing keys MUST NOT be in the repository, images, or the enclave. Only public keys ship in images.
- SEC-4: All data from the monitored network is untrusted. Parsers MUST bound input sizes and cap field lengths before feature extraction.
- SEC-5: Containers MUST run as non-root with `cap_drop: [ALL]` plus only what is needed, `no-new-privileges`, and read-only root where possible.
- SEC-6: No secrets in images, logs, or version control. Use environment files that are git-ignored.
- SEC-7: The outbound self-test MUST stay behind lab mode and MUST be disabled by default.
- SEC-8: The dashboard and API MUST bind to the enclave network only and require authentication with analyst/administrator roles.
- SEC-9: Do not log raw flow payload fields beyond what the schema defines. Do not log secrets or keys.

## 3. Architecture rules

- ARC-1: Follow `architecture.md`. If you must deviate, update `architecture.md` and add an ADR in the same PR.
- ARC-2: Keep service boundaries as defined. Detectors do not talk to PostgreSQL; only the evidence writer writes evidence.
- ARC-3: The evidence writer MUST remain single-writer and use a transaction with an advisory lock so the chain cannot fork.
- ARC-4: Streams MUST be bounded (approximate MAXLEN). Never create an unbounded queue, list or set per entity.
- ARC-5: Shard keys: primary by `src_ip`, secondary by `dst_ip`. Do not introduce new shard keys without an ADR.
- ARC-6: The bus MUST stay behind a small interface so Redis can be replaced (Kafka or Valkey) without touching detectors.
- ARC-7: Shared feature code (`engine/sentinel/features/`) MUST be used by both training and inference. No duplicated feature logic.

## 4. Detector rules

- DET-1: Every detector implements the `Detector` protocol and declares `name`, semver `version`, `loss_sensitivity`, correlation `group`, and ATT&CK technique.
- DET-2: Scores MUST be calibrated to [0, 1] before leaving the detector.
- DET-3: Every signal MUST carry `evidence` and `contributions`. A signal without evidence MUST NOT be emitted.
- DET-4: Per-entity state MUST use sketches (HyperLogLog, Count-Min) or fixed-size windows. No unbounded growth.
- DET-5: Detectors MUST be deterministic for a given input and seed.
- DET-6: Detectors MUST tolerate missing and late data (loss, gaps, reordering). Missing data lowers confidence; it MUST NOT raise exceptions.
- DET-7: Every detector MUST have: unit tests, a labelled attack scenario, an evasive variant, and a no-alert-on-benign test.
- DET-8: Thresholds and weights live in versioned config, not in code. Parameters used for an alert are recorded with the alert.
- DET-9: Do not add detectors, models, or algorithm families beyond the plan (Isolation Forest, Random Forest/XGBoost, statistics, sketches) without an ADR.
- DET-10: Exceptions inside a detector MUST be isolated per entity, counted, and surfaced in health. Repeated failures disable that detector with a health warning.

## 5. Scoring and explainability rules

- EXP-1: Fusion follows `architecture.md` section 9 (group maximum, noisy-OR, visibility modifier). Changes need an ADR and updated tests.
- EXP-2: Explanation values MUST be computed (SHAP or rule weights). Never hardcode contribution numbers.
- EXP-3: SHAP runs asynchronously, only above the alert threshold, and MUST NOT block the hot path.
- EXP-4: Alerts on encrypted sessions MUST state that inspection was metadata-only.
- EXP-5: Visibility Health MUST be recorded with every alert and displayed in the UI. Shedding MUST be reported, never silent.

## 6. Python rules

- PY-1: Python 3.14 baseline (3.13 supported). Do not move to 3.15 until the ML wheels support it.
- PY-2: Full type hints. `mypy` clean. `ruff` format and lint clean.
- PY-3: Pydantic models for all external schemas (flow, signal, alert, API payloads).
- PY-4: No blocking calls inside async code (no sync DB or Redis calls, no `time.sleep`, no heavy CPU work in the event loop).
- PY-5: Hot-path code: batch Redis reads and writes, pipeline sketch updates, vectorise with NumPy, avoid per-flow object churn.
- PY-6: Use multiple worker processes for detectors. Do not rely on free-threaded Python.
- PY-7: Use `structlog` JSON logging. No `print` in services.
- PY-8: No broad `except Exception: pass`. Handle specific errors; log and count the rest.
- PY-9: Use `uv` with the committed lockfile. Do not `pip install` ad hoc into the project environment.

## 7. Data and storage rules

- DAT-1: All timestamps are UTC. Alerts use ISO-8601 with `Z`. Internal times are float epoch seconds.
- DAT-2: Detectors use **event time** from the flow record, not processing time.
- DAT-3: Evidence hashing uses canonical JSON (sorted keys, no whitespace, UTF-8) and `prev_hash`. Never change the canonicalisation without a migration and ADR.
- DAT-4: Schema changes go through Alembic migrations in version control. Never edit the database by hand, except in the documented tamper demo.
- DAT-5: Malformed input goes to the dead-letter stream with a counter. It MUST NOT stop the pipeline.
- DAT-6: Alert schema v1.0 is a contract. Additive changes only; bump `schema_version` for anything else.

## 8. Frontend rules

- FE-1: React 19 with TypeScript in strict mode. No `any` without a comment explaining why.
- FE-2: Severity and health MUST NOT be conveyed by colour alone. Always include text or an icon.
- FE-3: Throttle live chart updates (1 to 2 per second) and use fixed-size ring buffers.
- FE-4: The UI MUST show passivity status (TX counter) and Visibility Health on the main screen.
- FE-5: Use current Vite 8, Tailwind 4 and Recharts 3 documentation. Do not copy older configs.
- FE-6: No remote assets (CDNs, web fonts, analytics). Everything is bundled for offline use.

## 9. Testing rules

- TST-1: Tests MUST be deterministic: fixed seeds, no wall-clock dependence, no network.
- TST-2: Every PR that changes a detector, fusion, or features MUST run the seeded replay regression. Detection or false-alert regressions fail the build.
- TST-3: Sketch code MUST have property tests (accuracy within stated error, mergeability).
- TST-4: After any XGBoost or SHAP upgrade, run the SHAP additivity smoke test.
- TST-5: After every test run that touches the stack, assert TX = 0 on the sensor interface.
- TST-6: Loss-tolerance tests at 1%, 5% and 10% injected loss are part of regression for correlation and visibility changes.
- TST-7: Never weaken or delete a test to make a build pass. Fix the cause or raise it.

## 10. Dependency rules

- DEP-1: Pin exact versions in lockfiles. Pin container images by digest.
- DEP-2: Ask before adding any new dependency. Justify need, licence, size, and maintenance state.
- DEP-3: Check licences against `docs/` tech stack section 6. Flag anything new that is not permissive.
- DEP-4: Respect the dependency freeze date. After the freeze: security fixes only, with a full regression run.
- DEP-5: No dependency may require network access at runtime.

## 11. Git and review rules

- GIT-1: Small, focused PRs. One concern per PR.
- GIT-2: Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
- GIT-3: PR description lists the rule IDs it touches, the requirement IDs it implements (FR-xx), and test evidence.
- GIT-4: Changes to `rules.md`, `architecture.md` or ADRs need review by at least one other person.
- GIT-5: Do not commit datasets, models, keys, `.env` files, or large binaries. Use git-ignored paths and checksums.
- GIT-6: Lockfile changes are reviewed like code.

## 12. Documentation rules

- DOC-1: Keep `architecture.md`, `task.md` and `memory.md` current in the same PR as the change.
- DOC-2: Every decision that changes the architecture gets an ADR (context, decision, consequences).
- DOC-3: Describe the software one-way link as an **emulation**. Never call it a hardware data diode unless hardware is actually used.
- DOC-4: Benchmark and evaluation reports state hardware, kernel, software versions, traffic mix, and duration.

## 13. Honesty and claims

- HON-1: Say what is measured, with the method. Say what is estimated, and label it.
- HON-2: Report failures too: the Red Team scorecard publishes where detection fails.
- HON-3: Do not call alert confidence a probability unless it has been calibrated and checked.
- HON-4: Documents distinguish verified facts from targets. Targets are labelled as targets.

## 14. Rules for AI coding agents

1. Read `rules.md`, `architecture.md`, `task.md` and `memory.md` before changing code.
2. Work on one task ID at a time. Confirm the task's definition of done before starting.
3. Do not invent numbers, benchmarks, versions, API names, or file paths. If unsure, check the repository or ask.
4. Never add code that makes network calls, even for convenience (downloads, telemetry, update checks).
5. Never relax an invariant, a test, or a type check to finish a task. Raise the conflict instead.
6. Ask before adding dependencies, changing schemas, changing shard keys, or changing fusion or hashing logic.
7. Run formatting, linting, type checks and the relevant tests before declaring a task done. Report what was actually run and its result.
8. Keep changes minimal and focused. Do not refactor unrelated code.
9. Update `task.md` (status) and `memory.md` (decisions, gotchas) when the work changes them.
10. When uncertain about security or passivity impact, choose the safer option and flag it.

## 15. Definition of Done (per task)

- [ ] Implements the task's requirement IDs and acceptance criteria.
- [ ] Complies with all rules above (list any rule IDs that were close calls).
- [ ] Tests added or updated; seeded regression passes; TX = 0 check passes.
- [ ] Lint, format and type checks pass.
- [ ] Docs updated (`architecture.md`, `task.md`, `memory.md`, ADR if needed).
- [ ] No new dependency without approval; lockfiles updated.
- [ ] Reviewed by a second person (or self-review checklist recorded for AI-authored changes).
