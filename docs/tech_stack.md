**SENTINEL-X**

Technology Stack Document

*Components, versions, rationale, compatibility and setup*

  -----------------------------------------------------------------------
  **Field**         **Detail**
  ----------------- -----------------------------------------------------
  Document version  1.0 (draft)

  Date              5 October 2026

  Companion         SENTINEL-X PRD v1.0 and Software Architecture and
  documents         Design Document v1.0

  Version basis     Baselines were checked against public release pages
                    and package listings on 5 October 2026. Re-check at
                    the dependency freeze (Section 4).

  Prepared by       \[Team name / authors\]

  Status            For team review before implementation
  -----------------------------------------------------------------------

**How to read this document.** Section 2 is the one-page summary.
Section 3 explains each choice, why it was made and what to watch for.
Section 4 lists version pairs that must be tested together and the
freeze policy. Sections 5 to 9 cover sizing, licences, alternatives,
repository layout and setup. Section 10 contains dependency manifests,
Section 11 known gotchas and Section 12 traceability to the
requirements.

1\. Purpose and Selection Principles

This document fixes the technology choices for SENTINEL-X so the team
can start building without re-debating tools. It records what is used,
the baseline version, why it was chosen, and the risks that come with
it.

1.1 Selection principles

  -----------------------------------------------------------------------
  **Principle**     **What it means for the stack**
  ----------------- -----------------------------------------------------
  Offline-first     Nothing may be fetched at runtime. Images and wheels
                    are built in a connected environment, then shipped as
                    offline bundles.

  Passive by        The sensor container has no network; tooling for
  construction      isolation and attestation (netns, tc, nftables) must
                    be available in the base OS.

  Explainable over  Tree models, statistics and sketches with SHAP and
  clever            rule contributions; no opaque deep models in the
                    first release.

  Boring,           Mature open-source projects with active releases and
  well-supported    good documentation; one tool per job.
  tools             

  Bounded resources Probabilistic data structures and partitioned streams
                    so memory and CPU stay predictable at the stated flow
                    rate.

  Demo-friendly     One-command start (Docker Compose), deterministic
                    seeded replay, fast UI updates.

  Licence-aware     Prefer permissive licences; flag anything that needs
                    review before redistribution (Section 6).
  -----------------------------------------------------------------------

2\. Stack at a Glance

![SENTINEL-X technology stack
layers](media/8af5958fa6c04ee2d587614ac495669b50f509e2.png "SENTINEL-X technology stack layers"){width="6.25in"
height="2.7604166666666665in"}

*Figure 1: Technology stack by layer (baseline versions as of October
2026).*

  ---------------------------------------------------------------------------------------
  **Layer**        **Technology**   **Baseline**     **Role**              **Licence**
  ---------------- ---------------- ---------------- --------------------- --------------
  Sensor           Zeek             9.0 LTS (8.0.x   Protocol analysis;    BSD-3-Clause
                                    LTS fallback)    conn, dns, ssl, http, 
                                                     capture-loss and      
                                                     stats logs            

  Fingerprints     JA4 and JA3 Zeek JA4 package      TLS client            See Section 6
                   packages         0.18.x           fingerprints for      
                                                     encrypted-session     
                                                     analysis              

  Replay / traffic tcpreplay,       Latest stable    Deterministic replay  GPL (demo
                   Scapy-based                       and labelled          tooling)
                   generator                         synthetic traffic     
                                                     (demo only)           

  Bus and state    Redis            8.8.x            Streams, HyperLogLog, RSALv2 /
                                                     Count-Min Sketch,     SSPLv1 /
                                                     T-Digest              AGPLv3
                                                                           (choice)

  Language         Python           3.14 (3.13       All backend services  PSF
                                    fallback)        and detectors         

  API              FastAPI with     FastAPI 0.141.x  REST, WebSocket,      MIT
                   Pydantic 2 and                    schema validation     
                   Uvicorn                                                 

  ML               scikit-learn     1.9.x            Isolation Forest,     BSD-3-Clause
                                                     Random Forest,        
                                                     calibration           

  ML               XGBoost          3.4.x            Gradient-boosted      Apache-2.0
                                                     classifiers           

  Explainability   SHAP             0.52.x           Per-alert feature     MIT
                                                     contributions         

  Numerics         NumPy, pandas,   Latest stable    Feature calculation   BSD-3-Clause
                   SciPy                             and offline training  

  Storage          PostgreSQL       18.x (18.6 in    Alerts, incidents,    PostgreSQL
                                    Aug 2026)        hash chain, health    Licence
                                                     samples               

  Frontend         React with       React 19.2.x     SOC dashboard         MIT
                   TypeScript                                              

  Frontend build   Vite and         Vite 8.x,        Dev server, bundling, MIT
                   Tailwind CSS     Tailwind 4.x     styling               

  Charts and graph Recharts, React  Recharts 3.10.x, Timelines, charts,    MIT
                   Flow             \@xyflow/react   evidence graph        
                                    12.x                                   

  Containers       Docker Engine    Latest stable    Packaging and         Apache-2.0
                   and Compose v2                    one-command deploy    

  Isolation        Linux netns, tc, Host kernel and  Receive-only capture  GPL (OS
                   nftables         iproute2         and egress drop       tooling)

  Quality          pytest,          Latest stable    Tests, linting,       Open source
                   Hypothesis,                       typing, UI smoke      
                   ruff, mypy,                       tests                 
                   Playwright                                              
  ---------------------------------------------------------------------------------------

3\. Component Selection in Detail

3.1 Sensor: Zeek

-   **Choice:** Zeek 9.0 LTS, which was released in mid-September 2026.
    The 8.0.x LTS line continues to receive patch releases until Zeek
    9.1 ships, so it is the fallback if a 9.0 image, package or the JA4
    package is not ready in your environment.

-   **Why:** Zeek produces structured connection, DNS, TLS and HTTP
    metadata, so the team does not need to write protocol parsers or
    reassemble streams. This is exactly the metadata-only input the
    product requires.

-   **Logs used:** conn, dns, ssl, http for detection; capture_loss and
    stats for Visibility Health.

-   **Output format:** enable JSON logs (redef LogAscii::use_json = T;)
    so the normaliser parses fields by name instead of by column
    position.

-   **Mode:** run Zeek standalone for the prototype. Cluster mode
    (ZeroMQ-based in Zeek 9) is the scale-out path if the benchmark
    shows Zeek is the bottleneck.

-   **Install:** use the official Docker images (series tags such as the
    LTS line) and record the exact image digest. Install Zeek packages
    with zkg at image build time; the runtime sensor has no network.

-   **Fallback:** PyShark or Scapy for a minimal path if Zeek cannot be
    installed on a team member\'s machine. Do not plan to use it for the
    benchmark.

-   **Watch out:** Zeek capture on Windows is not practical (the Windows
    libpcap build does not capture), so develop the sensor on Linux or
    in a Linux VM.

3.2 TLS fingerprints: JA4 and JA3 packages

-   **Choice:** install the FoxIO JA4 package with zkg (zeek/foxio/ja4).
    It adds ja4 and ja4s fields to ssl.log and adds TCP and
    timing-derived fields to conn.log.

-   **Compatibility:** the compiled plugin variant targets Zeek 7.0 and
    later; the script-only package supports Zeek 5 and later, with Zeek
    6 or later needed for QUIC. Test on the exact Zeek version you pin.

-   **Configuration:** individual JA4+ methods can be switched on or off
    in the package config. Enable only what the detectors use (ja4 and
    ja4s first).

-   **Secondary:** add a JA3 package from the Zeek package index if a
    second fingerprint helps rarity scoring.

-   **Licence:** see Section 6; the wider JA4+ family is under the FoxIO
    licence.

3.3 Streaming and state: Redis 8.8

-   **Choice:** Redis 8.8 (general availability in May 2026). Redis 8
    includes Bloom, Cuckoo, Count-Min Sketch, Top-K and T-Digest as
    built-in types, and HyperLogLog has been built in for years, so no
    separate module or Redis Stack image is needed.

-   **Streams:** XADD with approximate MAXLEN trimming, consumer groups
    per detector pool, XAUTOCLAIM for crashed consumers. Redis 8.8 adds
    XNACK so a consumer can explicitly release messages it cannot
    process.

-   **Sketches:** HyperLogLog (PFADD, PFCOUNT, PFMERGE; fixed 12 KB per
    key, about 0.81 percent standard error) for unique ports and hosts;
    Count-Min Sketch (CMS.\* commands) for destination heavy hitters;
    Top-K as an alternative for heavy hitters; T-Digest for latency
    percentiles on the benchmark panel.

-   **Client:** redis-py (asyncio) with the hiredis parser; batch with
    pipelines and read streams in batches (start with a few hundred
    messages per read and tune from the benchmark).

-   **Persistence:** hot state is reconstructible, so keep persistence
    simple (AOF every second or none). Durable evidence lives in
    PostgreSQL.

-   **Licence and alternative:** Redis 8 is offered under a choice of
    RSALv2, SSPLv1 or AGPLv3 (Section 6). Valkey (BSD fork) supports
    Streams and HyperLogLog; if you switch, check which probabilistic
    types it provides and implement Count-Min Sketch in-process if
    needed.

-   **Production path:** Kafka for retention and multi-node consumption;
    documented only, not built.

3.4 Backend runtime: Python, FastAPI and supporting libraries

-   **Python 3.14** is the baseline. Python 3.15 became final on 1
    October 2026, but scikit-learn 1.9 declares support for 3.11 to
    3.14, so stay on 3.14 (or 3.13) until the ML wheels you need support
    3.15.

-   **Concurrency:** use multiple worker processes for detectors (one
    per CPU share) instead of relying on free-threaded Python.
    Free-threading is officially supported from 3.14, but scientific
    wheel support varies; treat it as an experiment, not a dependency.

-   **API:** FastAPI with Pydantic 2 models for flow, signal and alert
    schemas, served by Uvicorn. FastAPI is pre-1.0 and releases
    frequently, so pin the exact version in the lockfile.

-   **Data access:** SQLAlchemy 2.x with psycopg 3 (async), Alembic for
    migrations.

-   **Speed helpers:** uvloop (Linux), orjson for JSON, NumPy
    vectorisation for feature updates, dataclasses with slots for
    hot-path objects.

-   **Profiling:** py-spy for sampling profiles during benchmark tuning.

-   **Environment management:** uv with a committed lockfile for
    reproducible installs.

3.5 Machine learning and explainability

-   **scikit-learn 1.9:** IsolationForest for unknown anomalies,
    RandomForestClassifier as an explainable baseline,
    CalibratedClassifierCV (isotonic or sigmoid) so scores behave like
    probabilities before fusion.

-   **XGBoost 3.4:** gradient-boosted classifiers for DGA,
    encrypted-session and exfiltration detection. Save models in
    XGBoost\'s native JSON or UBJ format, not as pickles.

-   **SHAP 0.52:** TreeExplainer for Random Forest and XGBoost. SHAP\'s
    XGBoost model parsing has changed across releases, so keep a smoke
    test that trains a tiny model and checks SHAP additivity; run it
    after any XGBoost or SHAP upgrade.

-   **Model artefacts:** sklearn models are pickled by joblib, and
    unpickling executes code. Verify the bundle signature before loading
    anything, and never load unsigned files.

-   **Training:** offline, outside the enclave, using one shared feature
    module for both training and inference to avoid train-serve skew.

-   **Later options:** LightGBM, or an autoencoder ensemble in the style
    of Kitsune, if time allows; both are deliberately out of the first
    release.

3.6 Storage: PostgreSQL 18

-   **Choice:** PostgreSQL 18 (18.6 as of August 2026). PostgreSQL 19
    was planned for autumn 2026; stay on 18 for the build and revisit
    only after the hackathon.

-   **Use:** alerts, incidents, Merkle roots, visibility and passivity
    samples, detector versions and benchmark runs (Design Document,
    Appendix A.2).

-   **JSONB:** store evidence and explanation as JSONB; index (entity,
    ts) for the dashboard and add GIN indexes only if queries need them.

-   **Evidence writer:** a single writer appends hash-chained records
    inside a transaction guarded by an advisory lock so the chain cannot
    fork.

-   **Operations:** pg_dump for quick demo resets; Alembic migrations in
    version control.

3.7 Frontend: React dashboard

-   **Stack:** React 19.2 with TypeScript, Vite 8, Tailwind CSS 4 (via
    the Vite plugin) and Recharts 3.

-   **Evidence graph and timeline:** React Flow (@xyflow/react 12.x) for
    the incident graph and attack progression view.

-   **Live updates:** a native WebSocket client with automatic
    reconnect; REST for lists and details (TanStack Query is optional
    but convenient).

-   **Performance:** throttle chart updates to one or two per second and
    keep a fixed-size ring buffer of recent points so the page stays
    smooth during a flood replay.

-   **Watch out:** Recharts 3 changed APIs compared with 2, and many
    tutorials still target 2. Vite 8 uses a new bundler core, so use
    plugin versions that declare Vite 8 support (for example
    \@vitejs/plugin-react 6).

-   **Theme:** dark SOC theme with colour-blind-safe severity colours
    and labels, not colour alone.

3.8 Security tooling and cryptography

-   **Signatures:** the cryptography package for Ed25519 sign and verify
    of update bundles; Python hashlib SHA-256 for the evidence chain and
    Merkle roots. No custom cryptography.

-   **Keys:** the signing key stays outside the sensor (on the build or
    release workstation); only the public key is baked into the image.

-   **Container hardening:** non-root users, read-only root filesystem,
    cap_drop ALL with only what is needed, no-new-privileges, tmpfs for
    temporary files, images pinned by digest.

-   **Passivity tooling:** iproute2 (ip, tc) and nftables in the monitor
    image; statistics read from the sensor interface counters.

-   **Optional:** an open-source image scanner such as Trivy in the
    build pipeline.

3.9 Packaging, deployment and host OS

-   **Docker Engine with Compose v2:** multi-stage Dockerfiles, Compose
    profiles (core, demo) so the replayer and generator exist only in
    the demo profile.

-   **Offline delivery:** build on a connected machine, then export
    images with docker save, compress, checksum and import with docker
    load on the enclave host.

-   **Host:** an Ubuntu LTS machine or VM. Network namespaces, tc and
    nftables need a real Linux kernel, so if you develop on Windows or
    macOS, run the sensor stack in a Linux VM rather than relying on a
    desktop container runtime.

-   **Reproducibility:** pin image digests, commit lockfiles, and record
    the host kernel version in the benchmark report.

3.10 Testing, quality and CI

-   **pytest** with pytest-asyncio for services; **Hypothesis** for
    property tests of sketches (accuracy and mergeability).

-   **ruff** for linting and formatting, **mypy** for type checks,
    pre-commit hooks to enforce both.

-   **Playwright** for dashboard smoke tests (alert appears, health
    strip changes, verification fails after tamper).

-   **Seeded replay regression:** CI replays the labelled scenario set
    and fails if detection or false-alert rate regresses.

-   **Benchmark harness:** custom scripts that report throughput and
    p50/p95/p99 latency with hardware details (PRD FR-53).

3.11 Observability

-   Structured JSON logging (structlog) and Prometheus-format metrics
    via prometheus-client, exposed inside the enclave only.

-   Per-stage latency histograms; T-Digest in Redis feeds the live
    percentile panel on the dashboard.

-   Grafana only in a developer profile, not in the enclave deliverable.

4\. Compatibility and Version Policy

4.1 Pairs that must be tested together

  -----------------------------------------------------------------------
  **Pair**         **Constraint**              **Action**
  ---------------- --------------------------- --------------------------
  Python and       scikit-learn 1.9 supports   Stay on Python 3.14 (or
  scikit-learn     Python 3.11 to 3.14.        3.13); do not use 3.15
                                               yet.

  XGBoost and SHAP SHAP\'s XGBoost parsing has Keep a SHAP additivity
                   changed between releases.   smoke test; run after any
                                               upgrade of either library.

  Zeek and JA4     Compiled plugin needs Zeek  Test on Zeek 9.0; fall
  package          7.0 or later; QUIC needs    back to 8.0.x LTS or the
                   Zeek 6 or later.            script-only package.

  Redis and        CMS, Top-K and T-Digest are Use redis-py command
  clients          built into Redis 8.         namespaces for them, or
                                               raw commands, and add a
                                               startup check that the
                                               commands exist.

  Vite and plugins Vite 8 changed its bundler  Use \@vitejs/plugin-react
                   core.                       6 and plugins that declare
                                               Vite 8 support.

  React and        Recharts 3 API differs from Follow Recharts 3
  Recharts         2.                          documentation; check peer
                                               dependencies on install.

  PostgreSQL and   Major version 18 is         Use psycopg 3; avoid
  drivers          current.                    features introduced after
                                               18.
  -----------------------------------------------------------------------

4.2 Version policy

-   Commit lockfiles (uv.lock and the npm or pnpm lockfile) and pin
    container images by digest.

-   Upgrade only when the seeded replay regression and the benchmark
    pass on the new set.

-   **Dependency freeze:** stop upgrading at least two weeks before the
    final demo (date: \[fill in\]). After the freeze only security fixes
    with a full regression run are allowed.

-   Record the exact versions used in the benchmark report.

5\. Resource Plan (8 cores, 16 GB target)

These are starting allocations to be tuned with the benchmark harness.
Treat CPU figures as shares (not hard limits); the benchmark decides the
final split.

  ----------------------------------------------------------------------------
  **Service**           **CPU       **Memory**   **Notes**
                        share**                  
  --------------------- ----------- ------------ -----------------------------
  sensor (Zeek)         2 cores     2 GB         Measure Zeek separately; it
                                                 can limit throughput before
                                                 Python does.

  normaliser            1 core      0.5 GB       Parsing and publishing; batch
                                                 reads from the log volume.

  detector workers (x4) 4 processes 3 GB         One shard group per process;
                                                 scale by shard count.

  redis                 1 core      2 GB         Streams with bounded length
                                                 plus sketch keys.

  correlator,           1 core      1 GB         Single instances; evidence
  evidence-writer,                               writer is deliberately
  monitor                                        single-writer.

  postgres              1 core      2 GB         Alerts and evidence; modest
                                                 write rate.

  api and frontend      0.5 core    0.5 GB       FastAPI and nginx.

  Headroom              \-          about 5 GB   Operating system and page
                                                 cache.
  ----------------------------------------------------------------------------

-   **Hot-path rule:** per-flow Python overhead is the main risk. Batch
    stream reads, update sketches in pipelines, vectorise window maths
    with NumPy and avoid creating many small objects per flow.

-   **Scale-out:** add detector processes first, then more Zeek workers,
    before considering any rewrite of the hot path in another language.

-   **Report honestly:** the benchmark report states the hardware,
    kernel, versions and traffic mix used.

6\. Licensing and Compliance Notes

This is an engineering summary, not legal advice. Confirm licence terms
before any redistribution or commercial use.

  -------------------------------------------------------------------------
  **Component**          **Licence**        **Note**
  ---------------------- ------------------ -------------------------------
  Zeek                   BSD-3-Clause       Permissive.

  scikit-learn           BSD-3-Clause       Permissive.

  XGBoost                Apache-2.0         Permissive.

  FastAPI, React, Vite,  MIT                Permissive.
  Tailwind, Recharts,                       
  React Flow, SHAP                          

  PostgreSQL             PostgreSQL Licence Permissive.

  Redis 8.x              Choice of RSALv2,  Fine for an internal prototype.
                         SSPLv1 or AGPLv3   If you ever offer SENTINEL-X as
                                            a service or distribute it,
                                            review the chosen licence.
                                            Valkey (BSD) is the
                                            alternative.

  FoxIO JA4+ package     FoxIO License 1.1  FoxIO states it has no patent
                         (JA4+ family)      claims on the JA4 TLS client
                                            fingerprint, but the other JA4+
                                            methods are under the FoxIO
                                            licence and commercial use
                                            needs a separate licence.
                                            Enable only the methods you
                                            need and review before
                                            commercial use.

  tcpreplay, Scapy       GPL (copyleft)     Used only for demo traffic and
                                            generation; not linked into the
                                            product.

  Datasets (CIC-IDS,     Dataset-specific   Check usage terms; do not
  CTU-13, UNSW-NB15)     terms              redistribute raw datasets in
                                            the repository.
  -------------------------------------------------------------------------

7\. Alternatives Considered

  -----------------------------------------------------------------------------
  **Choice**     **Alternative**            **Why not now**
  -------------- -------------------------- -----------------------------------
  Zeek           Suricata, Scapy-only       Suricata is signature-centric; a
                 pipeline                   Scapy-only pipeline needs a lot of
                                            parsing code and is slow. Zeek
                                            gives structured metadata directly.

  Redis Streams  Kafka, RabbitMQ            Kafka is heavier to run on one
                                            host; Redis also hosts the
                                            sketches. Kafka stays as the
                                            documented production path.

  Redis 8        Valkey                     Valkey is BSD-licensed, but
                                            probabilistic types differ.
                                            Reconsider if licence terms become
                                            a problem.

  PostgreSQL     ClickHouse, TimescaleDB,   Alert volume is far lower than flow
                 Elasticsearch/OpenSearch   volume, so a relational store with
                                            JSONB is enough and simpler to
                                            verify.

  Python hot     Go or Rust workers         Higher performance but more build
  path                                      effort and a split codebase.
                                            Optimise Python first; revisit only
                                            if the benchmark requires it.

  scikit-learn   LightGBM, PyTorch          Comparable boosting (LightGBM) adds
  and XGBoost    autoencoders               nothing new; deep models are harder
                                            to explain and tune in the time
                                            available.

  React and      Vue, Svelte, Grafana       Team already plans React; a custom
  Recharts       dashboards                 dashboard is needed for
                                            attestation, health and \'Why was I
                                            alerted?\' views that Grafana does
                                            not model well.

  FastAPI        Django REST, Flask         FastAPI gives typed schemas, native
                                            async and WebSocket support with
                                            less code.
  -----------------------------------------------------------------------------

8\. Repository Layout

sentinel-x/

compose.yaml \# profiles: core, demo

Makefile .env.example

infra/

netns/ \# veth + namespace setup, teardown, attestation helpers

nftables/ \# output chain policy for the sensor namespace

tc/ \# egress drop filters

sensor/

Dockerfile zeek/local.zeek zeek/packages.txt \# zkg packages installed
at build

engine/

pyproject.toml uv.lock

sentinel/

common/ \# schemas, config, hashing, time utils

normaliser/ detector/ correlator/ evidence/ monitor/ bundles/

detectors/ \# c2, dga, dns_tunnel, scan, ddos, syn, udp_amp, tls, exfil

features/ \# shared by training and inference

models/ \# signed model bundles (not committed raw)

tests/

api/ \# FastAPI app and routers

frontend/ \# React + TypeScript + Vite

traffic/

generator/ scenarios/ replay/ \# seeded, labelled

bench/ \# benchmark harness and report templates

docs/ \# PRD, design document, tech stack, ADRs

Directory names match the services in the design document\'s deployment
view, so a Compose service maps to one folder.

9\. Environment Setup

9.1 Prerequisites

-   Linux host or VM (Ubuntu LTS) with Docker Engine and Compose v2;
    root access for the namespace setup script.

-   uv for Python environments, Node.js (current LTS) with npm or pnpm
    for the frontend.

-   A connected build machine for pulling images and wheels; the enclave
    host can stay offline.

9.2 Typical workflow

\# Python environment from the lockfile

uv sync \--python 3.14

\# Frontend dependencies

npm ci \--prefix frontend

\# Build images (connected machine); zkg packages are installed at build
time

docker compose \--profile demo build

\# Create the receive-only namespace and capture interface (root)

sudo make netns-up

\# Start the stack and replay a seeded scenario

docker compose \--profile demo up -d

make replay SCENARIO=c2_beacon SEED=42

\# Verify passivity and the evidence chain

make attest

make verify-chain

\# Benchmark and export offline bundle

make bench

docker save \$(docker compose config \--images) \| gzip \>
sentinel-x-images.tar.gz

The make targets are placeholders to implement; the commands show the
intended flow.

10\. Dependency Manifests

Lower bounds below are minimums; the lockfiles pin exact versions.
Packages marked with a verified baseline in Section 2 use that version
as the floor.

10.1 engine/pyproject.toml (excerpt)

\[project\]

name = \"sentinel-engine\"

requires-python = \"\>=3.13,\<3.15\"

dependencies = \[

\"fastapi\>=0.141\",

\"uvicorn\[standard\]\>=0.30\",

\"pydantic\>=2.8\",

\"redis\[hiredis\]\>=5.0\",

\"psycopg\[binary\]\>=3.2\",

\"sqlalchemy\>=2.0\",

\"alembic\>=1.13\",

\"numpy\>=2.0\",

\"pandas\>=2.2\",

\"scipy\>=1.13\",

\"scikit-learn\>=1.9,\<2\",

\"xgboost\>=3.4,\<4\",

\"shap\>=0.52\",

\"joblib\>=1.4\",

\"cryptography\>=43\",

\"orjson\>=3.10\",

\"structlog\>=24\",

\"prometheus-client\>=0.20\",

\"uvloop\>=0.19; sys_platform == \'linux\'\",

\]

\[dependency-groups\]

dev = \[\"pytest\>=8\", \"pytest-asyncio\>=0.23\", \"hypothesis\>=6\",
\"ruff\>=0.5\", \"mypy\>=1.10\", \"scapy\>=2.5\"\]

10.2 frontend/package.json (excerpt)

{

\"dependencies\": {

\"react\": \"\^19.2.8\",

\"react-dom\": \"\^19.2.8\",

\"recharts\": \"\^3.10.0\",

\"@xyflow/react\": \"\^12.11.0\"

},

\"devDependencies\": {

\"vite\": \"\^8.1.0\",

\"@vitejs/plugin-react\": \"\^6.0.1\",

\"tailwindcss\": \"\^4.0.0\",

\"@tailwindcss/vite\": \"\^4.0.0\",

\"typescript\": \"\^5.9.0\",

\"@playwright/test\": \"latest\"

}

}

Run the compatibility checks in Section 4.1 after the first install,
then commit the lockfiles.

11\. Known Gotchas

  --------------------------------------------------------------------------
  **Area**        **Gotcha**                  **Mitigation**
  --------------- --------------------------- ------------------------------
  Python 3.15     Final release arrived on 1  Stay on 3.14 or 3.13;
                  October 2026; ML wheels may re-evaluate after the
                  lag.                        hackathon.

  New Zeek LTS    Zeek 9.0 is very recent;    Pin by digest; keep an 8.0.x
                  packages and images may lag LTS fallback image ready.
                  or behave differently.      

  JA4 plugin      Plugin build and Zeek       Build in CI against the pinned
                  version must match.         Zeek; fail the build if
                                              ssl.log lacks ja4.

  Redis licensing Redis 8 licensing differs   Read Section 6; keep the bus
                  from older BSD releases.    behind a small interface so
                                              Valkey or Kafka can replace
                                              it.

  Pickle risk     joblib models execute code  Verify signatures before load;
                  on load.                    use native XGBoost model
                                              files.

  SHAP drift      SHAP and XGBoost internals  Additivity smoke test in CI.
                  change across releases.     

  Windows/macOS   Namespaces, tc and Zeek     Use a Linux VM for the sensor
  dev             capture need Linux.         stack.

  Docker          A container with            Test the attach order; add a
  networking      network_mode none has no    health check that the capture
                  interface until the setup   interface exists.
                  script attaches one.        

  Frontend majors Vite 8, Tailwind 4 and      Use current official docs;
                  Recharts 3 differ from      avoid copying old configs.
                  older tutorials.            

  FastAPI pace    Pre-1.0 and frequent        Pin exact versions; upgrade
                  releases.                   only with green regression.
  --------------------------------------------------------------------------

12\. Traceability to Requirements

  -----------------------------------------------------------------------
  **Requirement group        **Primary technologies**
  (PRD)**                    
  -------------------------- --------------------------------------------
  Passive ingestion (FR-01   Zeek, tcpreplay, Linux netns, tc, nftables,
  to FR-04)                  Docker, Redis Streams

  Detectors (FR-10 to FR-19) Python, NumPy, Redis HyperLogLog and
                             Count-Min Sketch, scikit-learn, XGBoost, JA4
                             package

  Correlation and            Python, SHAP, React Flow, PostgreSQL
  explanation (FR-20 to      
  FR-24)                     

  Trust features (FR-30 to   iproute2, nftables, Zeek capture-loss and
  FR-34)                     stats logs, hashlib, cryptography (Ed25519),
                             PostgreSQL

  Alerting and dashboard     FastAPI, WebSocket, React, TypeScript, Vite,
  (FR-40 to FR-44)           Tailwind, Recharts

  Replay, tests and          tcpreplay, Scapy, pytest, Hypothesis,
  benchmark (FR-50 to FR-53) Playwright, Redis T-Digest, custom harness

  Non-functional: throughput Partitioned Redis Streams, sketches,
  and latency                multi-process Python workers, uvloop, orjson

  Non-functional:            uv and npm lockfiles, Docker Compose, image
  reproducibility            digests, offline image bundles
  -----------------------------------------------------------------------

Appendix A. References

Primary sources for the versions and behaviours referenced in this
document.

Sensor and fingerprints

-   [[Zeek: get Zeek (current LTS and feature
    releases)]{.underline}](https://zeek.org/get-zeek/) - release status

-   [[Zeek: installing
    Zeek]{.underline}](https://docs.zeek.org/en/current/install.html) -
    Docker images, packages, platforms

-   [[Zeek: how to use JA4 fingerprints in
    Zeek]{.underline}](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/) -
    zkg install and log fields

-   [[FoxIO JA4+
    releases]{.underline}](https://github.com/FoxIO-LLC/ja4/releases) -
    Zeek plugin and licence terms

Streaming, storage and runtime

-   [[RedisBloom
    README]{.underline}](https://github.com/RedisBloom/redisbloom) -
    built into Redis 8; licence choice

-   [[Redis 8.8.0
    release]{.underline}](https://github.com/redis/redis/releases/tag/8.8.0) -
    general availability notes

-   [[PostgreSQL 18.6 release
    notes]{.underline}](https://www.postgresql.org/docs/release/18.6/) -
    minor release details

-   [[PEP 790: Python 3.15 release
    schedule]{.underline}](https://peps.python.org/0790) - release dates
    and support window

Python libraries

-   [[scikit-learn 1.9
    changelog]{.underline}](https://scikit-learn.org/stable/whats_new/v1.9.html) -
    supported Python versions

-   [[XGBoost release
    notes]{.underline}](https://xgboost.readthedocs.io/en/latest/changes/) -
    3.x release history

-   [[SHAP
    releases]{.underline}](https://github.com/shap/shap/releases) -
    TreeExplainer and XGBoost notes

-   [[FastAPI
    documentation]{.underline}](https://fastapi.tiangolo.com) -
    framework docs
