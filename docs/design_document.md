**SENTINEL-X**

Software Architecture and Design Document

*Passive, read-only network threat detection for one-way monitored
networks*

  -----------------------------------------------------------------------
  **Field**         **Detail**
  ----------------- -----------------------------------------------------
  Document version  1.0 (draft)

  Date              4 October 2026

  Structure         arc42 template (12 sections) plus appendices

  Companion         SENTINEL-X Product Requirements Document v1.0
  document          (requirement IDs FR-xx / NFR are referenced here)

  Prepared by       \[Team name / authors\]

  Status            For team review before implementation
  -----------------------------------------------------------------------

**How to read this document.** Sections 1 to 4 explain what is being
built and why the architecture looks the way it does. Sections 5 to 7
describe the building blocks, runtime behaviour and deployment. Sections
8 to 11 cover cross-cutting concepts, decisions, quality scenarios and
risks. The appendices hold schemas, algorithm specifications, API
endpoints, a Compose skeleton and references.

1\. Introduction and Goals

1.1 Requirements overview

SENTINEL-X is a passive network threat-detection system for monitoring
enclaves protected by one-way links. It ingests packet and flow
metadata, runs several detectors, correlates weak signals into
explainable incidents, and exposes them through a live SOC dashboard.
The full requirements are in the PRD; the table below groups them by the
architectural concern they drive.

  ------------------------------------------------------------------------
  **Concern**      **Essential requirements**             **PRD
                                                          reference**
  ---------------- -------------------------------------- ----------------
  Passive          Read-only capture or replay; no        FR-01 to FR-04
  ingestion        outbound activity from the sensor      

  Multi-threat     DDoS, SYN flood, UDP amplification,    FR-10 to FR-19
  detection        scan/recon, C2, DGA, DNS tunnelling,   
                   encrypted-session anomalies,           
                   exfiltration                           

  Correlation and  Incidents, ATT&CK mapping, risk        FR-20 to FR-24
  explanation      fusion, per-alert explanations         

  Trust features   Passivity attestation, visibility      FR-30 to FR-34
                   health, hash-chained evidence, signed  
                   offline updates                        

  Alerting and UI  Standard JSON schema, REST +           FR-40 to FR-44
                   WebSocket, SOC dashboard               

  Test and proof   Replay, synthetic generator, Red Team  FR-50 to FR-53
                   mode, benchmark harness                
  ------------------------------------------------------------------------

1.2 Quality goals

  -------------------------------------------------------------------------------
  **Priority**   **Quality goal**   **What it means here**
  -------------- ------------------ ---------------------------------------------
  1              Provable passivity The sensor has no usable transmit path to the
                                    monitored network, and this can be shown
                                    live.

  2              Explainable        Every alert carries evidence and a computed
                 detection          explanation; incidents read as attack
                                    stories.

  3              Throughput and     A stated flow rate is sustained with measured
                 latency            p50/p95/p99 detection latency.

  4              Honest visibility  The system measures what it fails to see
                                    (loss, gaps, lag) and adjusts confidence.

  5              Evidence integrity Stored alerts are tamper-evident through a
                                    hash chain.
  -------------------------------------------------------------------------------

1.3 Stakeholders

  -----------------------------------------------------------------------
  **Role**            **Expectation**
  ------------------- ---------------------------------------------------
  SOC analyst         Understand an alert within seconds; trust the
                      evidence; see related alerts grouped.

  Incident responder  Reconstruct timelines; verify evidence has not been
                      altered.

  Security engineer   Deploy with one command; verify isolation; tune
                      detectors safely.

  Evaluators / judges See live detection, credible benchmark numbers and
                      honest limits.

  Development team    Clear module boundaries, testable detectors,
                      reproducible demo.
  -----------------------------------------------------------------------

2\. Architecture Constraints

2.1 Technical constraints

  --------------------------------------------------------------------------
  **ID**   **Constraint**              **Consequence for the design**
  -------- --------------------------- -------------------------------------
  TC-1     No outbound packets from    Capture interface has no address and
           the sensor toward the       no route; egress is dropped at
           monitored network.          multiple layers; flow records leave
                                       the sensor only via a one-way log
                                       volume.

  TC-2     Metadata only: no payload   Features come from headers, sizes,
           decryption or payload       timing, DNS names and TLS handshake
           storage.                    metadata.

  TC-3     No internet access at       No live threat-intel lookups; models,
           runtime.                    rules and intelligence arrive as
                                       signed offline bundles.

  TC-4     Prototype runs on one       Scale-out by adding worker replicas
           commodity host (target 8    on one host; Kafka and multi-node are
           cores, 16 GB).              documented as future options.

  TC-5     Linux containers            Network namespaces, tc and nftables
           orchestrated with Docker    are available for isolation.
           Compose.                    

  TC-6     Open-source components      Zeek, Redis, PostgreSQL,
           only; Python as the main    scikit-learn, XGBoost, SHAP, FastAPI,
           language.                   React.
  --------------------------------------------------------------------------

2.2 Organisational constraints

-   Small team and a fixed hackathon timeline; P0 requirements come
    first (PRD Section 15).

-   The demo must run offline and be reproducible from a seeded replay.

-   Only measured performance and accuracy numbers may be claimed.

2.3 Conventions

-   Alerts follow JSON schema v1.0 (PRD Section 11); timestamps are
    ISO-8601 UTC.

-   Detectors are versioned (name@semver) and each alert records the
    detector version.

-   Threat classes map to MITRE ATT&CK technique IDs.

-   Documentation follows arc42; code is formatted with a standard
    formatter and tested with pytest.

3\. Context and Scope

3.1 Business context

![SENTINEL-X context
diagram](media/32c99f9fef36c82f5113c5854fe03c0766660ec8.png "SENTINEL-X context diagram"){width="6.458333333333333in"
height="3.5104166666666665in"}

*Figure 1: Business context. The only inbound data path is the one-way
link; there is no path back.*

  -----------------------------------------------------------------------
  **Neighbour**     **Interaction**                     **Data**
  ----------------- ----------------------------------- -----------------
  Monitored network Source of mirrored traffic via the  Packets / flow
                    one-way link. SENTINEL-X never      metadata (inbound
                    sends anything back.                only)

  SOC analyst /     Views alerts, incidents and health  Alerts, evidence,
  responder         through the dashboard.              timelines

  Administrator     Deploys, configures and verifies    Configuration,
                    isolation.                          attestation
                                                        reports

  Offline media     Delivers signed model, rule and     Signed bundles
                    intelligence bundles.               (import only)
  -----------------------------------------------------------------------

3.2 Technical context

  ----------------------------------------------------------------------------
  **Interface**   **Direction**   **Protocol / format** **Notes**
  --------------- --------------- --------------------- ----------------------
  Capture         Inbound only    Ethernet frames       No IP, ARP and IPv6
  interface                       (AF_PACKET read) or   off; tc egress drop;
                                  PCAP replay           TX counters monitored.

  Zeek log volume Sensor to       Zeek TSV/JSON logs on Sensor container has
                  normaliser      a shared volume       no network; the volume
                                                        is the only exit.

  Internal bus    Inside enclave  Redis Streams         Docker internal
                                                        network without
                                                        external route.

  Dashboard / API Inside enclave  HTTPS REST, WebSocket Reachable only from
                                                        the enclave network.

  Bundle import   Inbound, manual Signed archive        Signature verified
                                  (model, rules, intel) before activation.
  ----------------------------------------------------------------------------

3.3 Scope boundaries

In scope: everything inside the monitoring enclave. Out of scope: the
monitored network itself, the physical data diode (emulated in software
for the prototype), response actions of any kind, and endpoint agents.

4\. Solution Strategy

  ------------------------------------------------------------------------
  **Quality goal /  **Approach**                              **Detail
  driver**                                                    in**
  ----------------- ----------------------------------------- ------------
  Provable          Layered isolation (no address, no route,  5.4, 7,
  passivity         tc egress drop, dropped capabilities,     ADR-009
                    internal-only network) with a live        
                    attestation panel and a lab-only outbound 
                    self-test.                                

  Explainable       Hybrid engine: transparent rules and      8.3, 8.4,
  detection         statistics first, then Isolation Forest   ADR-003,
                    and RF/XGBoost; SHAP for model            ADR-007
                    contributions; rule contributions for     
                    deterministic detectors.                  

  Throughput and    Partitioned Redis Streams, per-entity     8.2,
  latency           state in streaming sketches (HyperLogLog, ADR-004,
                    Count-Min), EWMA/CUSUM baselines,         ADR-005
                    horizontally scaled workers.              

  Honest visibility Visibility Health from capture loss,      8.5
                    drops, sequence gaps and queue lag,       
                    applied per detector as a confidence      
                    modifier; load shedding reported, never   
                    hidden.                                   

  Evidence          Single-writer hash chain with periodic    8.6, ADR-008
  integrity         Merkle roots and a verification tool.     

  Evasion           Multi-timescale windows, jitter-robust    Appendix C,
  resistance        periodicity, n-gram DGA models,           PRD FR-52
                    cumulative DNS counters, plus a Red Team  
                    scorecard.                                

  Deployability     Docker Compose with seeded replay; one    7
                    command to start; everything offline.     
  ------------------------------------------------------------------------

5\. Building Block View

5.1 Level 1: overall pipeline

![SENTINEL-X pipeline building
blocks](media/25426d07ff1b23d2d87d6cfefa469abef34e170f.png "SENTINEL-X pipeline building blocks"){width="5.552083333333333in"
height="5.625in"}

*Figure 2: Level 1 building blocks. Dashed red lines are the trust
subsystem (visibility and passivity).*

  -----------------------------------------------------------------------------
  **\#**   **Building       **Responsibility**                **Technology**
           block**                                            
  -------- ---------------- --------------------------------- -----------------
  1        Capture / replay Receive-only capture or PCAP      libpcap via Zeek;
                            replay; never transmits.          tcpreplay (demo)

  2        Sensor           Protocol analysis; writes conn,   Zeek (JA3/JA4 via
                            dns, ssl, http logs to a volume.  packages)
                            No network access.                

  3        Normaliser       Reads logs, maps to the internal  Python
                            flow schema, stamps sequence      
                            numbers, publishes to streams.    

  4        Stream bus       Partitioned streams and consumer  Redis Streams
                            groups; bounded length.           

  5        Detection        Maintain per-entity state, run    Python, NumPy,
           workers          detectors, emit calibrated        scikit-learn,
                            signals.                          XGBoost

  6        Correlator       Groups signals, fuses risk,       Python, SHAP
                            applies visibility modifier,      
                            computes explanations.            

  7        Incident engine  Builds incidents, maps ATT&CK and Python
                            kill-chain stage, builds          
                            timelines.                        

  8        Evidence writer  Single writer that appends        Python,
                            hash-chained records and Merkle   PostgreSQL
                            roots.                            

  9        Visibility       Computes Visibility Health and    Python
           monitor          load-shedding state.              

  10       Passivity        Reads TX counters and tc drop     Python, tc,
           monitor          stats; runs the lab-only outbound nftables
                            self-test.                        

  11       API              REST endpoints and WebSocket      FastAPI
                            push.                             

  12       Dashboard        SOC views, alert detail, \'Why    React, Tailwind,
                            was I alerted?\', attestation and Recharts
                            benchmark panels.                 

  13       Replay,          Labelled attack and benign        tcpreplay, Scapy,
           generator,       traffic, deterministic replay,    custom scripts
           benchmark        throughput and latency harness.   

  14       Bundle manager   Verifies signatures and activates Python, Ed25519
                            model, rule and intelligence      signatures
                            bundles.                          
  -----------------------------------------------------------------------------

5.2 Level 2: detection workers

  -----------------------------------------------------------------------
  **Sub-block**     **Responsibility**
  ----------------- -----------------------------------------------------
  Feature           Maintains sliding windows (10 s, 5 min, 1 h, 24 h)
  aggregator        per entity using time buckets and sketches; merges
                    buckets for longer windows.

  Detector plugins  One plugin per threat class, all implementing the
                    same interface (see below). Plugins are stateless
                    apart from the entity state they are given.

  ML scorer         Loads versioned Isolation Forest and RF/XGBoost
                    models, scores feature vectors, and computes SHAP
                    values for alerts above threshold (asynchronously).

  Detector registry Holds detector versions, thresholds, loss-sensitivity
                    coefficients and enable flags; supports activation
                    from signed bundles.

  Shedding          Reads queue lag; when lag exceeds limits, disables
  controller        lowest-priority work first (ML, then secondary
                    detectors) and reports it to the visibility monitor.
  -----------------------------------------------------------------------

class Detector(Protocol):

name: str

version: str

loss_sensitivity: float \# s_d in \[0,1\], see 8.5

def update(self, flow: Flow, state: EntityState) -\> None: \...

def evaluate(self, entity: str, now: float) -\> list\[\"Signal\"\]: \...

\@dataclass

class Signal:

entity: str \# e.g. source IP

threat_class: str \# e.g. C2_BEACONING

score: float \# calibrated 0..1

group: str \# correlation group, see 8.3

evidence: dict

contributions: list \# \[(signal_name, value), \...\]

window: tuple \# (start_ts, end_ts)

detector: str \# name@version

5.3 Level 2: correlator and incident engine

  -----------------------------------------------------------------------
  **Sub-block**     **Responsibility**
  ----------------- -----------------------------------------------------
  Signal grouper    Assigns each signal to a correlation group (volume,
                    periodicity, DNS, TLS, scan) so correlated evidence
                    is not double counted.

  Fusion            Combines group scores (noisy-OR with within-group
                    maximum), applies the visibility modifier and
                    computes confidence and severity.

  Explainer         Produces the \'Why was I alerted?\' breakdown: SHAP
                    values for ML signals, rule weights for deterministic
                    detectors, and marginal contribution per group at
                    incident level.

  Deduplicator      Suppresses repeats using the key (entity,
                    threat_class, time window) and updates last-seen
                    instead of re-alerting.

  Incident builder  Attaches alerts to an incident per entity when they
                    fall within a configurable gap, assigns kill-chain
                    stage and ATT&CK technique, and builds the timeline.
  -----------------------------------------------------------------------

5.4 Level 2: trust subsystem

  ------------------------------------------------------------------------
  **Sub-block**    **Responsibility**                     **Data sources**
  ---------------- -------------------------------------- ----------------
  Passivity        Publishes attestation: interface       Sensor namespace
  monitor          address state, routes, TX counters, tc statistics, tc
                   egress drop statistics, nftables       and nftables
                   policy, open sockets, effective        state
                   capabilities. Runs the lab-only        
                   outbound self-test on request.         

  Visibility       Computes Visibility Health (Appendix   Zeek
  monitor          C.5) and per-detector confidence       capture-loss and
                   modifiers; tracks shedding.            stats logs,
                                                          interface drops,
                                                          sequence gaps,
                                                          stream lag

  Evidence writer  Appends records with prev_hash and     Alert and
                   record hash; closes a Merkle root      incident records
                   every N records or T seconds; exposes  
                   verification.                          

  Bundle manager   Verifies Ed25519 signatures and hashes Offline bundle
                   before a bundle is activated; rejects  archive
                   anything unsigned or modified.         
  ------------------------------------------------------------------------

5.5 Key interfaces

  -----------------------------------------------------------------------
  **From**       **To**         **Channel**       **Payload**
  -------------- -------------- ----------------- -----------------------
  Sensor (Zeek)  Normaliser     Shared log volume conn, dns, ssl, http
                                                  logs

  Normaliser     Stream bus     Redis XADD        Normalised flow record
                                                  (Appendix A.1)

  Stream bus     Detection      Consumer groups   Flow records by shard
                 workers                          

  Detection      Correlator     Redis stream      Signal objects
  workers                       signals           

  Correlator     Incident       Internal queue    Fused alerts
                 engine                           

  Incident       Evidence       Internal queue    Alerts and incidents
  engine         writer                           

  Evidence       PostgreSQL     SQL               Hash-chained records
  writer                                          

  Monitors       Correlator /   Redis keys and    Visibility Health,
                 API            stream            attestation

  API            Dashboard      REST / WebSocket  JSON (Appendix B)
  -----------------------------------------------------------------------

6\. Runtime View

6.1 Steady-state flow to alert

  ----------------------------------------------------------------------------
  **Step**   **Component**    **Action**
  ---------- ---------------- ------------------------------------------------
  1          Capture / Zeek   Frames arrive on the RX-only interface; Zeek
                              writes metadata logs.

  2          Normaliser       Parses new log lines, maps fields, assigns a
                              per-sensor sequence number and event time,
                              computes shard keys, and publishes to the src
                              and dst streams.

  3          Detection worker Reads its shard, updates sketches and windows,
                              runs the detector plugins, and emits signals
                              whose score exceeds the detector\'s emit
                              threshold.

  4          Correlator       Groups signals, fuses risk, applies the
                              visibility modifier, deduplicates and computes
                              the explanation.

  5          Incident engine  Attaches the alert to an incident or opens a new
                              one; updates kill-chain stage and timeline.

  6          Evidence writer  Appends the alert to the hash chain and stores
                              it in PostgreSQL.

  7          API              Pushes the alert over WebSocket; the dashboard
                              updates without refresh.
  ----------------------------------------------------------------------------

6.2 C2 beaconing becomes an incident

  ----------------------------------------------------------------------------
  **Step**   **Component**    **Action**
  ---------- ---------------- ------------------------------------------------
  1          C2 detector      Collects connection timestamps per (src, dst,
                              port); after at least the minimum count it
                              computes the periodicity score (Appendix C.3).

  2          DNS detector     In parallel, flags high-entropy domains queried
                              by the same host (DGA score) and records the
                              signal in the DNS group.

  3          TLS detector     Scores a rare JA4 fingerprint for the same host
                              (TLS group).

  4          Correlator       Takes the maximum within each group, then
                              combines groups with noisy-OR; the visibility
                              modifier lowers confidence if loss is high.

  5          Incident engine  Creates one incident for the host with stage
                              \'command and control\' and a timeline of the
                              earlier DGA and TLS signals.

  6          Dashboard        Shows one incident with evidence, group
                              contributions and the timeline instead of three
                              unrelated alerts.
  ----------------------------------------------------------------------------

6.3 Degraded visibility (packet loss)

  ----------------------------------------------------------------------------
  **Step**   **Component**    **Action**
  ---------- ---------------- ------------------------------------------------
  1          Visibility       Samples capture loss, interface drops, sequence
             monitor          gaps and queue lag every few seconds and
                              computes Visibility Health.

  2          Visibility       Publishes per-detector modifiers using each
             monitor          detector\'s loss sensitivity.

  3          Correlator       Applies the modifier to the confidence of
                              affected detectors and records the health value
                              in the alert.

  4          Dashboard        Shows the health strip turning amber/red and a
                              note explaining which detections are less
                              reliable.
  ----------------------------------------------------------------------------

6.4 Evidence verification and tamper demonstration

  ----------------------------------------------------------------------------
  **Step**   **Component**    **Action**
  ---------- ---------------- ------------------------------------------------
  1          Analyst          Triggers verification from the dashboard or CLI.

  2          Evidence service Recomputes each record hash from its canonical
                              content and previous hash, and checks Merkle
                              roots.

  3          Evidence service Reports success, or the first record at which
                              the chain breaks. In the demo, a record is
                              edited directly in the database first so the
                              failure is visible.
  ----------------------------------------------------------------------------

6.5 Incident replay

  ----------------------------------------------------------------------------
  **Step**   **Component**    **Action**
  ---------- ---------------- ------------------------------------------------
  1          Analyst          Selects a scenario, duration and rate in the
                              dashboard.

  2          API              Starts the replayer with the scenario and a
                              fixed random seed.

  3          Replayer         Writes labelled traffic to the capture interface
                              at the requested rate.

  4          Pipeline         Processes the traffic as in 6.1; the dashboard
                              reconstructs the incident live.

  5          Benchmark        Records throughput and latency percentiles
             harness          during the run.
  ----------------------------------------------------------------------------

6.6 Offline bundle import

  ----------------------------------------------------------------------------
  **Step**   **Component**    **Action**
  ---------- ---------------- ------------------------------------------------
  1          Administrator    Places a signed bundle on the import path.

  2          Bundle manager   Verifies the Ed25519 signature and file hashes
                              against the trusted public key.

  3          Detector         Activates new versions; keeps the previous
             registry         version for rollback.

  4          Evidence writer  Records the import event in the hash chain.
  ----------------------------------------------------------------------------

7\. Deployment View

![SENTINEL-X deployment
diagram](media/dde9ea5300d5443d0a446d593cf18f54c45e2901.png "SENTINEL-X deployment diagram"){width="4.385416666666667in"
height="6.666666666666667in"}

*Figure 3: Deployment on a single host with Docker Compose. The red
namespace is the sensor isolation boundary.*

  ------------------------------------------------------------------------
  **Service**       **Network**            **Notes**
  ----------------- ---------------------- -------------------------------
  replayer (demo    Writes to the capture  tcpreplay or generator; stands
  only)             veth peer              in for the monitored network
                                           and diode.

  sensor            Own namespace, capture Zeek only. CAP_NET_RAW for
                    interface only, no IP  capture, all other capabilities
                                           dropped, read-only root, writes
                                           logs to a volume.

  normaliser        enclave_net            Reads the Zeek log volume
                                           read-only; publishes to Redis.

  redis             enclave_net            Streams, HyperLogLog and
                                           Count-Min Sketch keys (all
                                           built into Redis 8, no separate
                                           module needed).

  detector x N      enclave_net            Scaled replicas; each owns a
                                           set of shards.

  correlator,       enclave_net            Single instance each; the
  evidence-writer                          evidence writer is deliberately
                                           single-writer.

  postgres          enclave_net            Alerts, incidents, hash chain,
                                           health samples, benchmark runs.

  api, frontend     enclave_net; frontend  FastAPI and nginx serving the
                    also on ui_net         React build; the published port
                    (host-only bridge,     is bound to the enclave-facing
                    outbound NAT disabled) address only.

  monitor           enclave_net plus read  Visibility and passivity
                    access to sensor       monitors.
                    interface statistics   
  ------------------------------------------------------------------------

7.1 Sensor isolation (layers)

-   **No identity:** the capture interface has no IPv4/IPv6 address, ARP
    and IPv6 are disabled, and there are no routes.

-   **Egress drop at the device:** a tc clsact egress filter drops
    everything on the capture interface. This matters because raw
    AF_PACKET sends bypass nftables output hooks.

-   **Netfilter policy:** an nftables output chain with policy drop
    covers normal sockets.

-   **Least privilege:** the sensor container drops all capabilities
    except those needed for capture, runs read-only and has no network
    other than the capture interface.

-   **Observable evidence:** the monitor reads interface TX counters
    (expected 0) and tc drop counters (attempted egress), and publishes
    them to the attestation panel.

-   **Honest limit:** these controls are only as strong as the host
    configuration. The real guarantee in production is a hardware data
    diode or receive-only TAP; SPAN/mirror ports are bidirectional and
    are not a substitute.

\# Illustrative setup for the demo emulation (run as root on the host)

ip netns add sentinel_cap

ip link add veth_rep type veth peer name veth_cap

ip link set veth_cap netns sentinel_cap

ip link set veth_rep up

ip netns exec sentinel_cap ip link set veth_cap up promisc on

ip netns exec sentinel_cap ip link set veth_cap arp off

ip netns exec sentinel_cap sysctl -w net.ipv6.conf.all.disable_ipv6=1

\# drop everything leaving the capture device (covers raw sends)

ip netns exec sentinel_cap tc qdisc add dev veth_cap clsact

ip netns exec sentinel_cap tc filter add dev veth_cap egress matchall
action drop

\# drop locally generated packets from normal sockets

ip netns exec sentinel_cap nft add table inet sx

ip netns exec sentinel_cap nft add chain inet sx out \'{ type filter
hook output priority 0 ; policy drop ; }\'

\# attestation sources

ip netns exec sentinel_cap cat
/sys/class/net/veth_cap/statistics/tx_packets

ip netns exec sentinel_cap tc -s filter show dev veth_cap egress

7.2 Demo versus production

  ------------------------------------------------------------------------
  **Aspect**    **Demo / prototype**        **Production target**
  ------------- --------------------------- ------------------------------
  One-way link  Software emulation (veth,   Hardware data diode or
                namespace, tc, nftables)    receive-only TAP; optional DIY
                                            diode as in the GIAC paper for
                                            a physical demo

  Input         PCAP replay and generator   Mirrored traffic via diode;
                                            NetFlow/IPFIX optional

  Scale         One host, worker replicas   Kafka and multiple detector
                                            nodes; Security Onion style
                                            forward and storage nodes

  Updates       Signed bundles on local     Signed bundles via controlled
                path                        media transfer

  Storage       Single PostgreSQL           Replicated storage and
                                            retention policy
  ------------------------------------------------------------------------

7.3 Benchmark environment

Benchmarks must state hardware, traffic mix and duration (template in
PRD Section 12.3). As a sizing reference, Security Onion documents
roughly 200 Mbps per Zeek worker; the Zeek stage can therefore bound
throughput before the Python stages do, so measure both separately.

8\. Cross-cutting Concepts

8.1 Domain model

  -----------------------------------------------------------------------
  **Concept**    **Description**
  -------------- --------------------------------------------------------
  Entity         The subject of detection: a source IP, a destination IP,
                 an (src, dst, port) channel, or a (src, parent domain)
                 pair.

  Flow           Normalised connection or DNS/TLS event (Appendix A.1).

  Signal         Output of one detector for one entity and window:
                 calibrated score, group, evidence, contributions.

  Alert          A fused, explained and deduplicated signal set with
                 severity and confidence, stored in the evidence chain.

  Incident       A set of alerts for one entity within a gap threshold,
                 with a kill-chain stage, ATT&CK techniques and a
                 timeline.

  Evidence       An immutable, hash-chained record of an alert, incident
  record         update, attestation sample or bundle import.
  -----------------------------------------------------------------------

8.2 Streaming, state and time

-   **Partitioning:** the primary stream is sharded by hash(src_ip) so
    each worker owns all state for a source and needs no locks.
    Many-to-one attacks (DDoS) are detected from a second stream sharded
    by dst_ip.

-   **Bounded state:** unique-port and unique-host counts use
    HyperLogLog (Redis PFADD/PFCOUNT, mergeable across time buckets);
    heavy hitters use Count-Min Sketch; rates use EWMA with CUSUM.
    Memory per entity is therefore constant.

-   **Time:** detectors use event time from the flow record. A small
    allowed lateness (initially 5 s) tolerates reordering; later events
    are counted in the current bucket and flagged.

-   **Windows:** time buckets of 1 s roll into 10 s, 5 min, 1 h and 24 h
    windows by merging sketches; long windows catch low-and-slow
    behaviour.

-   **Back-pressure:** streams have a maximum length with approximate
    trimming; consumer lag is monitored and feeds the shedding
    controller (8.5).

8.3 Scoring and risk fusion

-   Each detector emits a calibrated score in \[0, 1\] (rule scores are
    mapped through a monotone calibration fitted on labelled data; model
    scores are probability-calibrated).

-   Signals are assigned to correlation groups (volume, periodicity,
    DNS, TLS, scan). Within a group the maximum is used, so two views of
    the same behaviour are not double counted.

-   Incident risk is P = 1 - product over groups of (1 - max score in
    group), then adjusted by the visibility modifier (8.5).

-   Severity is derived from confidence and, if configured, asset
    criticality (Appendix C.6).

-   All parameters live in versioned configuration and are recorded with
    the alert so results are reproducible.

8.4 Explainability

-   **ML signals:** SHAP TreeExplainer values for Random Forest and
    XGBoost; Isolation Forest outputs are explained by the most
    deviating features against the entity or peer-group baseline.

-   **Rule signals:** the contribution of each condition (for example
    SYN rate versus baseline) is reported directly.

-   **Incident level:** each group\'s marginal contribution is P minus P
    without that group.

-   SHAP is computed asynchronously for alerts above threshold so it
    never blocks the hot path.

-   The dashboard also states when payloads are encrypted and the
    inspection was metadata-only.

8.5 Visibility health and load shedding

-   Visibility Health VH in \[0, 1\] combines capture loss, interface
    drops, sequence gaps and queue lag (Appendix C.5).

-   Each detector has a loss sensitivity s_d. Adjusted confidence is
    conf x (1 - s_d x (1 - VH)). Periodicity-based detection is the most
    sensitive because missed beacons break the pattern; count-based
    detectors are conservative under loss because counts only
    under-estimate.

-   When lag grows, the shedding controller disables the lowest-priority
    work first (ML scoring, then secondary detectors) and never silently
    drops: every shed action is recorded and lowers VH.

8.6 Evidence integrity

-   Single-writer service appends records: hash = SHA-256(canonical JSON
    of the record without hash fields, then prev_hash).

-   A Merkle root over each batch (every 100 records or 60 s) is stored;
    roots can optionally be signed with an Ed25519 key kept outside the
    sensor.

-   A verification routine recomputes the chain and reports the first
    inconsistent record.

-   This provides tamper evidence and chain of custody. It is not a
    distributed ledger and does not prevent deletion by someone with
    database access; deletion is detected by the chain break and root
    mismatch.

8.7 Security and hardening

-   Containers run as non-root with read-only root filesystems, dropped
    capabilities and no secrets in images.

-   The dashboard binds to the enclave network only; authentication and
    role separation (analyst, administrator) protect the API.

-   Bundles are verified before activation; unsigned input is rejected.

-   All inputs from the monitored network are untrusted: parsers are
    bounded, and field lengths are capped before feature extraction.

8.8 Observability

-   Structured JSON logs for every service; metrics (flows/s, lag,
    drops, detector timings, memory) exposed inside the enclave only.

-   Latency is measured per flow from event arrival at the normaliser to
    alert emission, so benchmark numbers come from the same
    instrumentation the dashboard shows.

8.9 Testing strategy

  ------------------------------------------------------------------------
  **Level**     **What is tested**            **How**
  ------------- ----------------------------- ----------------------------
  Unit          Feature calculators, scoring  pytest with fixed fixtures
                functions, fusion, hash chain 

  Property      Sketch accuracy and           Randomised tests against
                mergeability                  exact counts within stated
                                              error

  Detector      Each threat class detected on Seeded replay in CI; fails
  regression    its labelled scenario; no     if detection or false-alert
                alerts on benign set          rate regresses

  Evasion       Jittered C2, low-and-slow     Red Team generator and
                scan, wordlist DGA, slow      scorecard
                tunnelling                    

  Loss          Behaviour at 1%, 5%, 10% loss Loss injection into replay;
  tolerance                                   check confidence and health
                                              response

  Passivity     TX stays 0; egress drops      Automated check after every
                counted                       test run; lab self-test

  Performance   Throughput, latency           Benchmark harness with fixed
                percentiles, memory soak      hardware description
  ------------------------------------------------------------------------

8.10 Configuration and versioning

-   YAML configuration validated at start-up; thresholds, windows, group
    assignments and loss sensitivities are explicit.

-   Detector and model versions are semantic; the active versions are
    recorded in every alert and in the evidence chain.

8.11 Error handling

-   Malformed log lines go to a dead-letter stream with a counter; they
    never stop the pipeline.

-   Detector exceptions are isolated per entity and counted; repeated
    failures disable that detector and raise a health warning.

-   Database unavailability buffers alerts in Redis with a bounded
    length; overflow is counted and reflected in visibility.

9\. Architecture Decisions

  ---------------------------------------------------------------------------
  **ID**    **Decision**     **Rationale**            **Alternatives /
                                                      trade-offs**
  --------- ---------------- ------------------------ -----------------------
  ADR-001   Use Zeek as the  Produces structured      Scapy/PyShark: more
            metadata source. conn, dns, ssl and http  control but slow and
                             logs and handles         more code. Zeek adds a
                             protocol parsing and     heavier install and
                             reassembly; avoids       needs Linux.
                             writing a packet parser. 

  ADR-002   Redis Streams as Simple, fast, consumer   Kafka: better at scale
            the message bus. groups, easy in Compose, and retention, heavier.
                             and hosts HyperLogLog    Documented as the
                             and sketches.            production path.

  ADR-003   Hybrid           Explainable, cheap, and  Deep learning (for
            detection: rules each threat class gets a example autoencoder
            and statistics   suitable method; avoids  ensembles as in
            plus Isolation   one opaque model.        Kitsune): attractive
            Forest and                                for unsupervised use
            RF/XGBoost.                               but harder to explain
                                                      and tune in time.

  ADR-004   Shard the stream Per-source state stays   Single shared state
            by source IP,    local to one worker;     store: simpler but
            with a second    DDoS needs destination   contended. Two streams
            stream by        aggregation.             double publish cost.
            destination IP.                           

  ADR-005   Streaming        Bounded memory and       Exact sets: simpler and
            sketches for     mergeable windows at     exact but memory grows
            per-entity       high event rates.        with unique entities.
            state.                                    Accept small counting
                                                      error.

  ADR-006   Noisy-OR fusion  Transparent, easy to     Learned stacking model:
            with             explain to analysts and  possibly more accurate
            within-group     judges, handles          but needs data and is
            maximum.         correlated evidence.     harder to explain.

  ADR-007   SHAP for model   Computed, defensible     LIME or none: less
            signals, direct  explanations rather than consistent or no
            contributions    hand-set numbers.        explanation. SHAP adds
            for rules.                                compute, so it runs
                                                      asynchronously.

  ADR-008   Hash-chained     Delivers tamper evidence Distributed ledger:
            evidence log     and chain of custody at  adds complexity with no
            with Merkle      low cost.                benefit for a single
            roots; no                                 enclave.
            blockchain                                
            network.                                  

  ADR-009   Emulate the      Makes passivity          Claim a hardware diode:
            one-way link in  demonstrable without     not credible. Add a DIY
            software and     hardware while staying   or real diode if
            prove it with    honest.                  available.
            attestation;                              
            state this                                
            clearly.                                  

  ADR-010   Offline-only     Matches the constraint   Live reputation
            models, rules    that nothing can be      lookups: impossible in
            and intelligence fetched from outside.    a one-way enclave.
            via signed                                
            bundles.                                  

  ADR-011   PostgreSQL for   Right tool for each:     Single store: simpler
            durable          durable, queryable       but weaker at one of
            evidence; Redis  history versus fast      the two jobs.
            for hot state.   ephemeral state.         

  ADR-012   Zeek runs in a   Keeps the passivity      Zeek publishing
            no-network       boundary small and easy  directly to Redis:
            sensor; a        to attest.               fewer parts but the
            separate                                  sensor would need a
            normaliser reads                          network.
            its logs.                                 
  ---------------------------------------------------------------------------

10\. Quality Requirements

10.1 Quality scenarios

  --------------------------------------------------------------------------------
  **ID**   **Attribute**    **Scenario**                    **Measure**
  -------- ---------------- ------------------------------- ----------------------
  QS-1     Passivity        During a full test run          TX packets = 0; tc
                            including attack replays, the   drop counter
                            sensor namespace is inspected.  increments only on the
                                                            lab self-test.

  QS-2     Throughput       A seeded replay at the stated   Sustained rate
                            flow rate runs for the stated   achieved with dropped
                            duration.                       events reported;
                                                            hardware stated.

  QS-3     Latency          A port-scan scenario begins     p95 time from flow
                            during sustained load.          arrival to alert under
                                                            the target;
                                                            p50/p95/p99 reported.

  QS-4     Loss tolerance   5% packet loss is injected      Visibility Health
                            during a C2 replay.             drops; C2 confidence
                                                            is reduced by the s_d
                                                            rule; detection still
                                                            occurs or is flagged
                                                            as degraded.

  QS-5     Explainability   An analyst opens any alert.     Evidence and
                                                            contributions present;
                                                            contributions computed
                                                            (SHAP or rule
                                                            weights).

  QS-6     Integrity        A stored alert is modified      Verification fails at
                            directly in the database.       that record and
                                                            reports its ID.

  QS-7     Memory           Unique source IPs grow tenfold  Detector memory stays
                            during a soak test.             within the configured
                                                            ceiling.

  QS-8     Evasion          Beacons with 20% jitter and a   Detection rates
                            low-and-slow scan are replayed. published in the
                                                            scorecard, including
                                                            failures.

  QS-9     Deployability    A fresh machine runs the        All services healthy
                            documented start command.       and a replay works
                                                            with no internet.

  QS-10    Usability        A new viewer inspects an alert. Can state the threat,
                                                            source and reason
                                                            within about 30
                                                            seconds.
  --------------------------------------------------------------------------------

11\. Risks and Technical Debt

11.1 Technical risks

  ---------------------------------------------------------------------------
  **ID**   **Risk**                    **Mitigation**
  -------- --------------------------- --------------------------------------
  R-1      Python hot path cannot      Shard and scale workers, vectorise
           reach the target flow rate. feature updates, batch Redis calls,
                                       pre-aggregate; report the measured
                                       rate only.

  R-2      Zeek throughput or log      Measure Zeek separately; tune workers
           volume becomes the          and log selection; use sampling in
           bottleneck.                 benchmarks only if disclosed.

  R-3      Monitor cannot easily read  Prototype both approaches early
           statistics from the sensor  (shared PID namespace reading
           namespace.                  /proc/\<pid\>/net/dev, or host-side
                                       namespace access); keep the
                                       attestation interface the same.

  R-4      Capture-loss estimates are  Combine several signals (Zeek loss
           inaccurate or unavailable.  stats, interface drops, sequence gaps,
                                       lag); describe VH as an estimate.

  R-5      JA3/JA4 packages or         Pin Zeek and package versions in the
           versions differ between     image; test fingerprint extraction in
           environments.               CI.

  R-6      SHAP cost slows alerting.   Compute asynchronously and only above
                                       threshold; cache explainers.

  R-7      Dataset labels and domain   Cross-dataset tests, own labelled
           shift distort accuracy      traffic, document known dataset
           claims.                     issues.

  R-8      Evidence writer becomes a   Batch appends and Merkle roots; the
           bottleneck.                 alert rate is far below flow rate.

  R-9      Sketch error is             Document error bounds; test against
           misunderstood as detection  exact counts; keep thresholds well
           error.                      above error.
  ---------------------------------------------------------------------------

11.2 Known technical debt (accepted for the prototype)

-   Single-node deployment without high availability.

-   Basic authentication and role separation only; no external identity
    integration.

-   Simple retention policy for stored evidence and health samples.

-   Software emulation of the one-way link; hardware diode integration
    left for later.

12\. Glossary

  -----------------------------------------------------------------------
  **Term**          **Meaning**
  ----------------- -----------------------------------------------------
  ADR               Architecture decision record.

  ATT&CK            MITRE knowledge base of adversary tactics and
                    techniques.

  C2                Command and control channel between malware and
                    operator.

  Count-Min Sketch  Probabilistic structure estimating item frequencies
                    in fixed memory.

  CUSUM / EWMA      Methods for detecting shifts relative to a moving
                    baseline.

  Data diode        Device that physically permits data flow in one
                    direction only.

  DGA               Domain generation algorithm used by malware to create
                    many domain names.

  HyperLogLog       Probabilistic structure for counting distinct items
                    in small fixed memory.

  Incident          Group of related alerts for one entity, with a
                    kill-chain stage and timeline.

  JA3 / JA4         Fingerprints of TLS client handshake characteristics.

  Merkle root       Single hash summarising a batch of hashed records.

  SHAP              Method that attributes a model prediction to its
                    input features.

  Signal            Output of one detector for one entity and window.

  TAP               Network tap that copies traffic without being in the
                    data path.

  Visibility Health Estimate in \[0, 1\] of how completely the sensor is
                    seeing traffic.
  -----------------------------------------------------------------------

Appendix A. Data Model

A.1 Normalised flow record (stream payload)

  -----------------------------------------------------------------------
  **Field**                   **Type**      **Notes**
  --------------------------- ------------- -----------------------------
  sensor_id, seq              string, int64 Per-sensor monotonic sequence
                                            for gap detection.

  ts_start, ts_end            float (UTC    Event time.
                              seconds)      

  uid                         string        Zeek connection ID.

  src_ip, src_port, dst_ip,   mixed         Five-tuple.
  dst_port, proto                           

  service, conn_state,        string        From Zeek conn log;
  history                                   conn_state used for
                                            failed-connection ratio.

  duration, orig_bytes,       numeric       Volume and symmetry features.
  resp_bytes, orig_pkts,                    
  resp_pkts                                 

  dns_query, dns_qtype,       string        Present for DNS events.
  dns_rcode                                 

  tls_ja3, tls_ja4, tls_sni,  string        Present for TLS sessions when
  tls_version                               available.
  -----------------------------------------------------------------------

A.2 PostgreSQL tables

  -----------------------------------------------------------------------
  **Table**              **Key columns**
  ---------------------- ------------------------------------------------
  alerts                 alert_id, incident_id, ts, entity, threat_class,
                         technique, stage, severity, confidence,
                         visibility_health, evidence (jsonb), explanation
                         (jsonb), detector_version, hash, prev_hash

  incidents              incident_id, entity, first_seen, last_seen,
                         stage, techniques, risk, status

  merkle_roots           root_id, first_alert_id, last_alert_id,
                         root_hash, signature (optional), created_at

  visibility_samples     ts, health, capture_loss, drops, gaps, lag,
                         shedding

  passivity_samples      ts, tx_packets, tx_bytes, egress_drops,
                         nft_policy_hash, caps_hash

  detector_versions      name, version, activated_at, bundle_hash

  replay_runs /          run_id, scenario, seed, hardware, rate,
  benchmark_runs         duration, p50/p95/p99, dropped, peak_memory
  -----------------------------------------------------------------------

A.3 Redis keys and streams

  -----------------------------------------------------------------------
  **Key pattern**                **Purpose**
  ------------------------------ ----------------------------------------
  flows:src:{shard},             Partitioned flow streams (bounded
  flows:dst:{shard}              length).

  signals                        Detector output stream.

  hll:ports:{src}:{bucket},      Unique destination ports / hosts per
  hll:hosts:{src}:{bucket}       time bucket (merged for longer windows),
                                 with TTL.

  cms:dst:{bucket}               Count-Min Sketch for destination heavy
                                 hitters.

  ewma:{metric}:{entity}         EWMA mean and variance and CUSUM
                                 statistic.

  vh:current, vh:modifiers       Visibility Health and per-detector
                                 modifiers.

  dead:flows                     Dead-letter stream for malformed input.
  -----------------------------------------------------------------------

Appendix B. API Overview

  -----------------------------------------------------------------------
  **Method and path**            **Purpose**
  ------------------------------ ----------------------------------------
  GET /api/alerts                List alerts with filters (severity,
                                 threat class, entity, time range).

  GET /api/alerts/{id}           Alert detail including evidence and
                                 explanation.

  GET /api/incidents,            Incident list and detail with timeline
  /api/incidents/{id}            and graph data.

  GET /api/stats/summary         Counts by threat type, top sources,
                                 current rates.

  GET /api/health/visibility     Visibility Health and components.

  GET /api/health/passivity      Attestation: TX counters, egress drops,
                                 policy, capabilities.

  POST /api/selftest/outbound    Lab-only outbound attempt; returns
                                 blocked status (disabled outside lab
                                 mode).

  GET /api/evidence/verify       Verify the hash chain; returns first
                                 failing record if any.

  POST /api/replay/start, POST   Control scenario replay (local input
  /api/replay/stop               only).

  GET /api/benchmark/latest      Latest measured throughput and latency
                                 percentiles.

  WS /ws/live                    Push stream of alerts, incident updates
                                 and health changes.
  -----------------------------------------------------------------------

Appendix C. Algorithm Specifications

All numeric parameters are initial values to be tuned on labelled data
and recorded in versioned configuration.

C.1 Rate shift detection (EWMA and CUSUM)

-   EWMA mean: mu_t = a x_t + (1 - a) mu\_(t-1); variance tracked the
    same way; z_t = (x_t - mu_t) / sigma_t.

-   CUSUM: S_t = max(0, S\_(t-1) + (x_t - mu_t - k)); alert when S_t
    exceeds h. Typical start: k = 0.5 sigma, h = 5 sigma.

-   Used for packets/s, bytes/s, SYN/s, unique sources and DNS query
    rate.

C.2 Scan and reconnaissance score

-   For each source and window: U_h = distinct destination hosts (HLL),
    U_p = distinct destination ports (HLL), F = failed-connection ratio
    (conn_state such as S0 or REJ).

-   Fan-out score = 1 - exp(-(U_h / H0 + U_p / P0)), where H0 and P0 are
    scale constants learned per peer group.

-   Signal score combines fan-out and F; vertical, horizontal and mixed
    scans are labelled by which of U_p or U_h dominates.

-   Windows: 10 s, 5 min, 1 h, 24 h; the long windows catch low-and-slow
    scans.

C.3 Beaconing (periodicity) score

-   For each (src, dst, port) channel with at least N connections
    (initially 8), compute inter-arrival times.

-   Dominant-period fraction: share of intervals within +/- j% of the
    modal interval (histogram bins of 10% of the median); this tolerates
    jitter.

-   Autocorrelation peak of the binned connection series (1 s bins) at
    the best lag.

-   Size consistency: 1 minus the coefficient of variation of bytes per
    connection, clipped to \[0, 1\].

-   Score = 0.5 x dominant fraction + 0.3 x autocorrelation peak + 0.2 x
    size consistency (initial weights, to be tuned).

C.4 DGA and DNS tunnelling features

-   DGA: label length, Shannon entropy of the second-level label, digit
    ratio, consonant run length, character bigram/trigram log-likelihood
    under a model of benign domains, per-host NXDOMAIN rate. Classifier:
    XGBoost.

-   Wordlist-based DGAs defeat entropy, so the n-gram model and NXDOMAIN
    rate carry more weight for them.

-   DNS tunnelling: per (src, parent domain) unique subdomain count
    (HLL), mean subdomain length and entropy, share of TXT/NULL queries,
    bytes per query and query rate; cumulative counters catch slow
    tunnels.

C.5 Visibility Health

-   Components, each normalised to \[0, 1\]: L = capture loss scaled by
    a 10% cap, D = interface drop rate scaled by a cap, G = sequence-gap
    rate, Q = queue lag penalty.

-   VH = max(0, 1 - (0.4 L + 0.3 D + 0.2 G + 0.1 Q)) (initial weights).

-   Per-detector adjustment: conf_adj = conf x (1 - s_d x (1 - VH)).

-   Initial s_d: volumetric 0.3, scan 0.3, DNS 0.4, TLS 0.5, C2
    beaconing 0.6; tune with loss-injection experiments.

C.6 Fusion and severity

-   P = 1 - product over groups g of (1 - max score of signals in g).

-   Severity: P \>= 0.90 HIGH; 0.70 to 0.90 MEDIUM; 0.40 to 0.70 LOW;
    below 0.40 informational (not alerted). If asset criticality is
    configured, raise one level for critical assets.

Appendix D. Docker Compose Skeleton

An illustrative skeleton only. The capture interface is moved into the
sensor namespace by a setup script (7.1); service names match Figure 3.
The frontend joins a host-only bridge with outbound NAT disabled so its
port can be published while the rest of the stack stays on the internal
network.

x-engine: &engine

build: ./engine

networks: \[enclave_net\]

read_only: true

services:

sensor:

build: ./sensor

network_mode: \"none\" \# capture iface is attached by the setup script

cap_drop: \[ALL\]

cap_add: \[NET_RAW\] \# capture only; egress dropped by tc on the iface

read_only: true

volumes: \[\"zeeklogs:/logs\"\] \# only exit from the sensor

normaliser:

\<\<: \*engine

command: python -m sentinel.normaliser

volumes: \[\"zeeklogs:/logs:ro\"\]

redis:

image: redis:8.8 \# HLL and Count-Min Sketch are built in since Redis 8

networks: \[enclave_net\]

detector:

\<\<: \*engine

command: python -m sentinel.detector

deploy: { replicas: 4 }

correlator: { \<\<: \*engine, command: python -m sentinel.correlator }

evidence-writer: { \<\<: \*engine, command: python -m sentinel.evidence
}

monitor: { \<\<: \*engine, command: python -m sentinel.monitor }

postgres: { image: \"postgres:16\", networks: \[enclave_net\] }

api: { build: ./api, networks: \[enclave_net\] }

frontend:

build: ./frontend

networks: \[enclave_net, ui_net\]

ports: \[\"127.0.0.1:8080:80\"\]

networks:

enclave_net:

internal: true \# no external routing

ui_net:

driver: bridge

driver_opts:

com.docker.network.bridge.enable_ip_masquerade: \"false\" \# no outbound
NAT

volumes:

zeeklogs: {}

Appendix E. References

Public references used to shape this design. Vendor pages are marketing
material and are listed for terminology only.

Architecture documentation

-   [[arc42 documentation]{.underline}](https://docs.arc42.org/home/) -
    practical tips and worked examples for the twelve sections

-   [[arc42 template
    repository]{.underline}](https://github.com/arc42/arc42-template) -
    template sources and download formats

Network monitoring systems

-   [[Security Onion
    architecture]{.underline}](https://soc.readthedocs.io/en/latest/architecture.html) -
    forward, storage and master node model

-   [[Security Onion hardware
    guidance]{.underline}](https://soc.readthedocs.io/en/latest/hardware.html) -
    rough per-worker throughput for sizing

-   [[The Book of Zeek
    announcement]{.underline}](https://zeek.org/2021/02/just-released-new-and-improved-zeek-documentation/) -
    Zeek documentation overview

-   [[RITA (Active
    Countermeasures)]{.underline}](https://www.activecountermeasures.com/?p=2934) -
    beacon, DNS tunnelling and long-connection detection over Zeek logs

-   [[RITA
    releases]{.underline}](https://github.com/activecm/rita/releases) -
    source and releases

-   [[Kitsune (NDSS
    2018)]{.underline}](https://arxiv.org/pdf/1802.09089v1.pdf) - online
    unsupervised NIDS with autoencoder ensemble

One-way links and data diodes

-   [[GIAC paper: tactical data
    diodes]{.underline}](https://giac.org/paper/gicsp/242/tactical-data-diodes-industrial-automation-control-systems/142041) -
    building a simple data diode

-   [[Garland Technology: data diodes for federal
    networks]{.underline}](https://www.garlandtechnology.com/federal-data-diodes) -
    why SPAN is not acceptable in regulated deployments

-   [[Garland Technology: hardware data
    diodes]{.underline}](https://www.garlandtechnology.com/visibility-101-hardware-data-diodes) -
    receive-only monitoring ports

-   [[Data loss and retransmission in
    diodes]{.underline}](https://www.helpag.com/?p=34818) - reliability
    issues of one-way transfer

-   [[OPSWAT data diode
    guide]{.underline}](https://www.opswat.com/resources/guides/unidirectional-security-gateway-and-data-diode-guide) -
    diodes versus unidirectional gateways (vendor)

-   [[Waterfall data diodes vs gateways
    guide]{.underline}](https://waterfall-security.com/wp-content/uploads/2025/04/Data-Diodes-vs.-Unidirectional-Gateways-Guide.pdf) -
    terminology (vendor)
