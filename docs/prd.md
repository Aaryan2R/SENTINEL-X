**SENTINEL-X**

Product Requirements Document

*Passive, read-only network threat detection for one-way monitored
networks*

  -----------------------------------------------------------------------
  **Field**         **Detail**
  ----------------- -----------------------------------------------------
  Document version  1.0 (draft)

  Date              4 October 2026

  Project type      Hackathon prototype (NTRO problem statement: AI-based
                    threat detection over one-way traffic)

  Prepared by       \[Team name / authors\]

  Status            For team review. Verify requirements against the
                    official problem statement text.
  -----------------------------------------------------------------------

**Purpose of this document.** This PRD defines what SENTINEL-X must do,
for whom, under which constraints, and how success will be measured. It
is the single reference for scope, priorities and acceptance criteria
during the build and the demo.

1\. Executive Summary

SENTINEL-X is a passive, read-only network threat-detection system for
monitoring enclaves protected by one-way links (data diodes). It
consumes packet and flow metadata, runs several threat-specific
detectors alongside machine-learning anomaly models, correlates weak
signals into incidents, and presents evidence-backed alerts on a live
SOC dashboard.

**Core value proposition.** SENTINEL-X does not merely claim it cannot
touch the monitored network. It proves it, and it tells the analyst how
much traffic it failed to see.

Three pillars make the product distinct:

-   **Provable passivity:** a live attestation panel and an \'attempt
    outbound\' self-test show the sensor has no return path.

-   **Diode-aware visibility:** the system measures its own blind spots
    (packet loss, gaps, queue lag) and adjusts alert confidence
    accordingly.

-   **Evidence-chained incidents:** every alert is explainable and
    stored in a hash-chained, tamper-evident log, with related alerts
    grouped into one attack story.

2\. Problem and Context

Critical infrastructure (power, telecom, defence, government, hospitals,
airports) is often monitored through one-way links so that a compromised
monitoring system cannot be used to attack the protected network.
Conventional IDS/NDR tools assume capabilities that a one-way enclave
removes:

-   No active probing, handshakes, or scanning of suspicious hosts.

-   No live threat-intelligence or reputation lookups, and no cloud
    model updates.

-   No pushing of mitigation or firewall commands back into the network.

-   No retransmission: lost packets stay lost, so visibility is
    imperfect by design.

-   Payloads are frequently encrypted and must not be decrypted.

2.1 Threats in scope

DDoS, SYN flood, UDP amplification, botnet command-and-control (C2),
domain-generation algorithms (DGA), DNS tunnelling, encrypted-traffic
malware, port scanning, reconnaissance, and data exfiltration.

2.2 Stated requirements to satisfy

-   Passive ingestion of traffic (PCAP and/or flow records); read-only
    operation.

-   Detection across multiple threat classes, not a single classifier.

-   Standardised, structured alerts.

-   Streaming (continuous) operation rather than batch-only analysis.

-   A stated and demonstrated traffic rate that the solution was tested
    against.

3\. Goals and Non-Goals

3.1 Goals

-   **G1:** Detect the ten in-scope threat classes from metadata only,
    in a streaming pipeline.

-   **G2:** Make every alert explainable: evidence, contributing
    signals, and a plain-language reason.

-   **G3:** Group related alerts into incidents mapped to kill-chain
    stages and MITRE ATT&CK techniques.

-   **G4:** Make the read-only property demonstrable and verifiable, not
    just asserted.

-   **G5:** Report honest, measured throughput and detection latency
    from a reproducible benchmark.

-   **G6:** Be demo-ready with one command (docker compose up) and a
    deterministic incident replay.

3.2 Non-goals

-   Blocking, rate-limiting, IP banning, firewall changes or any other
    active response.

-   Active scanning, probing or any outbound traffic from the sensor.

-   Payload inspection, TLS decryption or storage of packet payloads.

-   Antivirus or endpoint protection.

-   Large deep-learning models or a broad zoo of ML algorithms.

-   Operating an actual blockchain network (a hash chain is used for
    evidence integrity only).

-   Production-grade hardware data diode (the prototype emulates one-way
    behaviour in software).

4\. Users and Personas

  -----------------------------------------------------------------------
  **Persona**      **Needs**                  **Key features**
  ---------------- -------------------------- ---------------------------
  SOC analyst      Quickly see what is        Dashboard, alert detail,
  (Tier 1)         happening, what is urgent, \'Why was I alerted?\',
                   and why an alert fired.    severity and confidence.

  Incident         Reconstruct an attack and  Incident timeline, evidence
  responder /      trust the evidence.        graph, hash-chained log,
  forensic                                    replay.
  investigator                                

  Security         Deploy, tune and verify    Docker Compose deploy,
  engineer /       the system and its         passivity attestation,
  administrator    isolation.                 visibility health, signed
                                              update bundles.

  Evaluator /      Verify requirements met    Live replay, benchmark
  judge (demo      and see credible numbers.  panel, alert schema,
  persona)                                    red-team scorecard.
  -----------------------------------------------------------------------

5\. Constraints and Design Principles

-   **Read-only by construction:** the capture interface has no IP
    address and no transmit path; egress is denied by policy.

-   **Metadata only:** features come from headers, sizes, timing, DNS
    names and TLS handshake metadata. No decryption.

-   **Offline-first:** all models, rules and intelligence are local;
    updates arrive as signed bundles.

-   **Loss-tolerant:** no component assumes complete data; missing data
    lowers confidence instead of breaking detection.

-   **Bounded resources:** per-entity state uses streaming sketches so
    memory does not grow with unique entities.

-   **Explainable first:** prefer models and detectors that can show
    their evidence over opaque scores.

-   **Claim only what is measured:** all performance and accuracy
    numbers come from the benchmark harness.

6\. Product Differentiators

  ----------------------------------------------------------------------------
  **Differentiator**   **What it is**                  **How it is
                                                       demonstrated**
  -------------------- ------------------------------- -----------------------
  Provable passivity   Receive-only capture in an      Attestation panel shows
                       isolated network namespace;     TX = 0; \'Attempt
                       live TX counters, firewall      outbound\' button fails
                       policy and socket list;         visibly.
                       outbound self-test.             

  Diode-aware          Visibility Health score from    Inject packet loss
  visibility           capture drops, sequence gaps,   during replay;
                       Zeek loss stats and queue lag;  dashboard lowers
                       applied as a confidence         confidence and flags
                       modifier.                       blind spots.

  Evidence-chained     Alerts hash-chained             Edit a stored record
  incidents            (prev_hash + hash) with         and show chain
                       periodic Merkle roots; related  verification fail.
                       alerts grouped into incidents.  

  Evasion-aware        Red Team mode generates evasive Scorecard: jittered
  detection            variants and reports detection  beacons, low-and-slow
                       rate per evasion level.         scans, wordlist DGA,
                                                       slow tunnelling.

  Scalable streaming   HyperLogLog, Count-Min Sketch   Benchmark panel:
  core                 and EWMA/CUSUM on partitioned   flows/sec, p50/p95/p99
                       streams.                        latency, memory under
                                                       growth.
  ----------------------------------------------------------------------------

7\. Functional Requirements

Priority: **P0** = required for the MVP demo, **P1** = important, **P2**
= stretch.

7.1 Ingestion

  -------------------------------------------------------------------------------
  **ID**   **Requirement**               **Pri.**   **Acceptance criteria**
  -------- ----------------------------- ---------- -----------------------------
  FR-01    Ingest PCAP files and         P0         Replaying a sample PCAP
           replayed or mirrored traffic             yields normalised flow
           via Zeek to produce conn,                records on the stream with no
           dns, ssl and http metadata.              manual steps.

  FR-02    Accept NetFlow/IPFIX records  P2         Sample IPFIX file is
           as an alternative input.                 normalised to the same
                                                    internal schema.

  FR-03    Normalise all inputs to one   P0         Per-source state is handled
           flow schema and publish to               by a single worker;
           partitioned Redis Streams (by            destination-keyed aggregation
           source IP; secondary stream              works for DDoS.
           by destination IP).                      

  FR-04    Perform no outbound activity: P0         TX counters on the capture
           no probes, handshakes, DNS               interface stay 0 for a full
           lookups or API calls.                    test run; egress is denied by
                                                    policy.
  -------------------------------------------------------------------------------

7.2 Detection

  -------------------------------------------------------------------------------
  **ID**   **Requirement**               **Pri.**   **Acceptance criteria**
  -------- ----------------------------- ---------- -----------------------------
  FR-10    Volumetric DDoS detector      P0         Detects a replayed flood
           using packets/s, bytes/s,                within the target latency;
           unique sources, source                   alert shows the contributing
           entropy and destination                  metrics.
           concentration against                    
           EWMA/CUSUM baselines.                    

  FR-11    SYN flood detector using SYN  P0         Detects SYN flood scenario;
           rate, SYN:ACK ratio and                  benign bursty traffic does
           incomplete handshakes.                   not trigger it in the benign
                                                    test set.

  FR-12    UDP amplification detector    P1         Detects replayed reflection
           using response/request byte              traffic with
           ratio, flow asymmetry and                response-to-request ratio in
           known amplification ports.               evidence.

  FR-13    Port scan and reconnaissance  P0         Distinguishes vertical,
           detector using unique                    horizontal and mixed scans;
           destination ports/hosts                  catches a low-and-slow
           (HyperLogLog),                           variant using the long
           failed-connection ratio,                 window.
           fan-out score, multiple time             
           windows.                                 

  FR-14    DGA detector using length,    P0         Scores DGA test domains above
           entropy, digit ratio, n-gram             threshold; common benign
           probability and NXDOMAIN                 domains below it.
           rate.                                    

  FR-15    DNS tunnelling detector using P1         Detects tunnelling replay;
           query length, subdomain                  cumulative detection works
           entropy, unique subdomains               for slow tunnelling.
           per parent domain, TXT/NULL              
           record use and query rate.               

  FR-16    C2 beaconing detector using   P0         Detects 30 s beacons with at
           inter-arrival periodicity                least 20% jitter in the Red
           robust to jitter (histogram              Team set.
           or autocorrelation).                     

  FR-17    Encrypted-session anomaly     P1         Dashboard marks such alerts
           detector using TLS/QUIC                  \'payload encrypted:
           metadata (JA3/JA4, packet                metadata-only inspection\'.
           sizes, timing, direction,                
           bursts). No decryption.                  

  FR-18    Exfiltration detector using   P1         Detects replayed bulk
           outbound volume and ratio                outbound transfer; normal
           versus per-host and                      backup-sized transfers are
           peer-group baselines.                    scored using baseline.

  FR-19    Behavioural anomaly layer:    P0         Models trained and versioned;
           Isolation Forest for unknown             per-class metrics reported by
           anomalies plus Random                    the evaluation harness.
           Forest/XGBoost for known                 
           classes.                                 
  -------------------------------------------------------------------------------

7.3 Correlation and explainability

  -------------------------------------------------------------------------------
  **ID**   **Requirement**               **Pri.**   **Acceptance criteria**
  -------- ----------------------------- ---------- -----------------------------
  FR-20    Incident engine groups        P0         A scripted multi-stage
           related alerts per entity                scenario yields one incident,
           into incidents with                      not separate unrelated
           kill-chain stage and MITRE               alerts.
           ATT&CK technique.                        

  FR-21    Risk scoring fuses signals    P0         Fusion method and parameters
           (log-odds or noisy-OR),                  are documented and
           discounts correlated signals,            reproducible.
           outputs confidence (0 to 1)              
           and severity.                            

  FR-22    \'Why was I alerted?\' shows  P0         Every alert carries an
           per-signal contributions:                explanation whose
           SHAP values for tree models              contributions are computed,
           and rule contributions for               not hand-set.
           detectors.                               

  FR-23    Threat evidence graph shows   P1         Clicking an incident renders
           entity, signals and incident             its graph from stored
           relationships.                           evidence.

  FR-24    Per-source attack timeline    P1         Timeline lists alerts in
           with progression stages.                 order with stage labels.
  -------------------------------------------------------------------------------

7.4 Trust and integrity

  -------------------------------------------------------------------------------
  **ID**   **Requirement**               **Pri.**   **Acceptance criteria**
  -------- ----------------------------- ---------- -----------------------------
  FR-30    Passivity Attestation panel:  P0         Panel values come from the
           live TX counters, firewall               host at runtime, not static
           policy, open sockets and                 text.
           namespace details.                       

  FR-31    \'Attempt outbound\'          P1         Test result recorded in the
           self-test tries to send a                evidence log.
           packet from the sensor and               
           reports that it was blocked.             

  FR-32    Visibility Health score from  P0         Injected loss measurably
           capture drops, sequence gaps,            lowers displayed health and
           Zeek loss stats and queue                alert confidence.
           lag; shown on the dashboard              
           and applied as a confidence              
           modifier.                                

  FR-33    Hash-chained evidence log     P1         Altering any record causes
           with a chain verification                verification to fail at that
           tool and tamper                          record.
           demonstration.                           

  FR-34    Offline signed update bundles P2         Unsigned or modified bundle
           for models, rules and                    is rejected.
           intelligence, verified on                
           import.                                  
  -------------------------------------------------------------------------------

7.5 Alerting and dashboard

  -------------------------------------------------------------------------------
  **ID**   **Requirement**               **Pri.**   **Acceptance criteria**
  -------- ----------------------------- ---------- -----------------------------
  FR-40    Emit alerts in the standard   P0         Schema validated
           JSON schema (Section 11).                automatically in tests.

  FR-41    REST API (alerts, incidents,  P0         Dashboard updates without
           stats, health) and WebSocket             page refresh.
           push for live updates.                   

  FR-42    SOC dashboard: live traffic,  P0         Main screen shows these
           active alerts, threat-type               elements with live data.
           counts, top suspicious                   
           sources, visibility and                  
           passivity status.                        

  FR-43    Alert detail view with        P0         All fields from the schema
           evidence, explanation,                   are visible.
           severity, confidence,                    
           first/last seen.                         

  FR-44    Analyst feedback (true/false  P2         Feedback is persisted and
           positive) stored locally to              reportable.
           inform threshold tuning.                 
  -------------------------------------------------------------------------------

7.6 Replay, testing and benchmarking

  -------------------------------------------------------------------------------
  **ID**   **Requirement**               **Pri.**   **Acceptance criteria**
  -------- ----------------------------- ---------- -----------------------------
  FR-50    Incident replay: choose       P0         Replay is deterministic and
           scenario, duration and rate;             runs without external network
           dashboard reconstructs the               access.
           incident.                                

  FR-51    Synthetic traffic generator   P0         Generator produces labelled
           for normal traffic and each              PCAP/flows for every in-scope
           attack class.                            threat.

  FR-52    Red Team mode: evasive        P1         Scorecard covers jittered C2,
           variants with a                          low-and-slow scan, wordlist
           detection-rate scorecard.                DGA, slow tunnelling.

  FR-53    Benchmark harness reporting   P0         Single command produces a
           throughput and p50/p95/p99               report; only measured numbers
           detection latency with                   are published.
           hardware details.                        
  -------------------------------------------------------------------------------

8\. Non-Functional Requirements

Numeric targets below are goals to validate. Published figures must be
the measured values from the benchmark harness.

  -----------------------------------------------------------------------------
  **Category**      **Requirement**           **Target / verification**
  ----------------- ------------------------- ---------------------------------
  Throughput        Sustain the stated flow   Target 50,000 flows/s on 8 cores
                    rate end to end (ingest   / 16 GB; verify with benchmark
                    to alert).                and report actual.

  Latency           Low delay from flow       Target p95 under 1 s; report
                    arrival to alert.         p50/p95/p99.

  Memory            State per entity is       Soak test with growing unique
                    bounded using sketches.   sources; memory stays within a
                                              fixed ceiling.

  Passivity         No transmit path from     Zero egress packets in test;
                    sensor.                   policy and counters shown in
                                              attestation panel.

  Loss tolerance    Degrade gracefully under  Test at 1%, 5% and 10% loss;
                    packet loss.              confidence drops and visibility
                                              health reflects it.

  Explainability    Every alert has evidence  100% of alerts include an
                    and explanation.          explanation block (automated
                                              check).

  Accuracy          Low false positives on    Report false alerts per hour on
                    benign traffic.           benign sets alongside per-class
                                              precision/recall.

  Reproducibility   One-command deployment.   docker compose up brings up all
                                              services; seeded replay gives the
                                              same alerts.

  Security          Hardened, minimal sensor. Read-only containers, no
                                              unnecessary ports, no secrets in
                                              images, signed bundles.

  Privacy           Metadata only.            No payload storage or decryption
                                              anywhere in the pipeline.

  Usability         Alert is understandable   New viewer can explain an alert
                    at a glance.              from the detail screen within
                                              about 30 seconds.
  -----------------------------------------------------------------------------

9\. System Architecture

Data flows one way from the monitored network into the sensor. The only
interface exposed to people is the dashboard, which is served inside the
monitoring enclave.

Monitored network \--\> \[ one-way link / data diode \] \--\> Sensor
(receive-only NIC, no IP)

\|

v

Zeek / PyShark \--\> Flow normaliser \--\> Redis Streams (keyed by src
IP / dst IP)

\|

v

Detection workers: rules + sketches \| behavioural ML \| threat-specific
detectors

\|

v

Correlation + risk scoring + SHAP explanations \--\> Incident engine

\|

v

Hash-chained evidence store (PostgreSQL) \--\> FastAPI (REST +
WebSocket) \--\> React SOC dashboard

  -----------------------------------------------------------------------
  **Component**     **Responsibility**
  ----------------- -----------------------------------------------------
  Capture / replay  Receive-only interface or PCAP replay; no transmit.
                    Emits packets to Zeek.

  Zeek (or PyShark) Generates connection, DNS, TLS and HTTP metadata,
                    including JA3/JA4 where available.

  Flow normaliser   Maps all inputs to the internal schema; stamps
                    sequence info for gap detection.

  Redis Streams     Partitioned message bus; consumer groups for parallel
                    workers (Kafka noted as production option).

  Detection workers Rules, HyperLogLog/Count-Min sketches, EWMA/CUSUM,
                    Isolation Forest, Random Forest/XGBoost.

  Correlation       Fuses signals, maps to ATT&CK and kill-chain stage,
  engine            builds incidents and timelines.

  Visibility        Computes Visibility Health from drops, gaps, Zeek
  monitor           stats and queue lag.

  Passivity monitor Reads TX counters, firewall policy and sockets; runs
                    the outbound self-test.

  Evidence store    PostgreSQL; hash-chained alert records and incident
                    data.

  API and dashboard FastAPI (REST + WebSocket); React, Tailwind and
                    Recharts front end.
  -----------------------------------------------------------------------

10\. Detector Specifications

  -----------------------------------------------------------------------------------------------
  **Threat**      **Key features**    **Method**                    **ATT&CK**   **Evasion to
                                                                                 test**
  --------------- ------------------- ----------------------------- ------------ ----------------
  DDoS /          pkts/s, bytes/s,    EWMA/CUSUM + rules            T1498        Ramp-up and
  volumetric      unique sources,                                                pulsing floods
                  source entropy,                                                
                  destination                                                    
                  concentration                                                  

  SYN flood       SYN rate, SYN:ACK   Rules + ratio thresholds      T1498.001    Distributed
                  ratio, incomplete                                              low-rate SYN
                  handshakes                                                     

  UDP             response/request    Rules + RF                    T1498.002    Uncommon
  amplification   bytes, asymmetry,                                              reflector ports
                  amplification ports                                            

  Port scan /     unique dst          HyperLogLog + multi-window    T1046, T1018 Low-and-slow,
  recon           ports/hosts, failed rules                                      randomised order
                  ratio, fan-out                                                 

  Botnet C2       inter-arrival       Histogram/autocorrelation +   T1071, T1573 Jitter, sleep
                  periodicity,        RF                                         randomisation
                  destination                                                    
                  repetition, size                                               
                  symmetry                                                       

  DGA             length, entropy,    Char n-gram model +           T1568.002    Wordlist-based
                  digit ratio,        RF/XGBoost                                 DGA
                  n-grams, NXDOMAIN                                              
                  rate                                                           

  DNS tunnelling  query length,       Rules + cumulative counters   T1071.004    Slow, low-volume
                  subdomain entropy,                                             tunnelling
                  unique subdomains,                                             
                  TXT use                                                        

  Encrypted       JA3/JA4, packet     XGBoost + rarity of           T1573        Mimicking common
  malware         sizes/timing,       fingerprint                                fingerprints
                  direction, bursts                                              

  Exfiltration    outbound bytes,     Baseline + Isolation Forest   T1041, T1048 Chunked,
                  in/out ratio, new                                              throttled
                  destinations                                                   transfer
  -----------------------------------------------------------------------------------------------

11\. Alert and Evidence Schema

All alerts share one JSON structure. Explanation contributions are
computed by SHAP (tree models) or by the detector\'s rule weights; the
values below are illustrative.

{

\"schema_version\": \"1.0\",

\"alert_id\": \"A-001842\",

\"incident_id\": \"INC-0097\",

\"timestamp\": \"2026-10-04T18:22:41Z\",

\"flow_id\": \"F-928173\",

\"source_ip\": \"10.20.14.56\",

\"destination_ip\": \"185.x.x.x\",

\"destination_port\": 443,

\"threat_class\": \"C2_BEACONING\",

\"attack_technique\": \"T1071\",

\"kill_chain_stage\": \"command_and_control\",

\"severity\": \"HIGH\",

\"confidence\": 0.962,

\"visibility_health\": 0.97,

\"evidence\": {

\"beacon_interval_s\": 30.2,

\"interval_variance_s\": 1.7,

\"connections\": 18,

\"tls_fingerprint\": \"JA4-xxxx\",

\"bytes_out\": 42000,

\"bytes_in\": 11000

},

\"explanation\": \[

{ \"signal\": \"periodicity\", \"contribution\": 0.31 },

{ \"signal\": \"rare_tls_fingerprint\", \"contribution\": 0.24 }

\],

\"detector_version\": \"c2-beacon@0.3.1\",

\"evidence_hash\": \"sha256:\<hash\>\",

\"prev_hash\": \"sha256:\<hash\>\"

}

12\. Evaluation and Benchmark Plan

12.1 Data

-   Public datasets: CIC-IDS2017/2018, CTU-13 (botnet), UNSW-NB15.
    CIC-IDS2017 has documented labelling issues; note and handle this in
    the report.

-   Public domain lists for benign and DGA domains, plus domains
    generated by the team\'s own generators.

-   Self-generated labelled traffic from the synthetic generator and the
    replay library.

12.2 Metrics

-   Per-class precision, recall and F1 (not accuracy alone).

-   False alerts per hour on benign traffic.

-   Cross-dataset generalisation: train on one dataset, test on another.

-   Detection latency (p50/p95/p99) and sustained throughput, with
    hardware and test conditions stated.

-   Red Team scorecard: detection rate per evasion level.

-   Behaviour under packet loss (1%, 5%, 10%) and under memory soak.

12.3 Benchmark report template

  -----------------------------------------------------------------------
  **Item**               **Value (fill from measurements)**
  ---------------------- ------------------------------------------------
  Hardware               CPU cores / RAM / OS

  Traffic rate tested    flows/s and packets/s, duration

  Traffic mix            benign vs attack proportions

  Detection latency      p50 / p95 / p99

  Alert generation time  median and max

  Peak memory            MB at end of soak test

  Dropped events         count and percentage
  -----------------------------------------------------------------------

13\. Demo Plan

The demo starts at \'SYSTEM NORMAL\' and escalates through scenarios on
a live replay. Keep architecture explanation to a minimum and let the
dashboard tell the story.

  ----------------------------------------------------------------------------
  **Time**   **Event**              **Expected dashboard response**
  ---------- ---------------------- ------------------------------------------
  0:00       Normal traffic         Risk LOW; passivity panel shows TX = 0;
                                    visibility health green.

  0:15       Port scan begins       RECONNAISSANCE alert with evidence (hosts,
                                    ports, window, failed ratio).

  0:30       DGA traffic            DGA activity alert; domain scores and
                                    features shown.

  0:45       Periodic C2 traffic    C2 beaconing alert; related alerts merge
                                    into one incident with timeline.

  1:00       SYN flood              SYN flood / DDoS alert; throughput and
                                    latency counters visible.

  1:15       Packet loss injected   Visibility health drops; alert confidence
                                    adjusts.

  1:30       \'Attempt outbound\'   Outbound blocked; edited record fails
             and tamper test        hash-chain verification.

  1:45       Benchmark panel        Measured flows/s and latency percentiles
                                    displayed.
  ----------------------------------------------------------------------------

**Fallback:** keep a pre-recorded run of the replay in case of
live-environment issues.

14\. Technology Stack

  ------------------------------------------------------------------------
  **Layer**        **Choice**                  **Notes**
  ---------------- --------------------------- ---------------------------
  Capture /        Zeek (primary),             Zeek produces metadata
  metadata         PyShark/Scapy (fallback)    directly; run in
                                               Docker/Linux.

  Streaming        Redis Streams               Kafka mentioned as
                                               production scale-out.

  Backend          Python, FastAPI             REST + WebSocket.

  Streaming        Redis HyperLogLog,          Bounded-memory state.
  algorithms       Count-Min Sketch,           
                   EWMA/CUSUM                  

  ML               scikit-learn, XGBoost,      Isolation Forest + Random
                   pandas, NumPy, SHAP         Forest/XGBoost only.

  Database         PostgreSQL                  Alerts, incidents, hash
                                               chain.

  Frontend         React, Tailwind, Recharts   SOC dashboard.

  Deployment       Docker Compose (frontend,   One command to start;
                   backend, redis, postgres,   network namespace and
                   ml-engine, sensor)          nftables for isolation.

  Traffic          iperf3, scripted DNS/HTTP,  Labelled, reproducible.
  generation       custom attack generators    
  ------------------------------------------------------------------------

15\. Delivery Plan

Phases are indicative; adjust durations to the hackathon schedule.

  ----------------------------------------------------------------------------
  **Phase**      **Focus**              **Deliverables**     **Exit criteria**
  -------------- ---------------------- -------------------- -----------------
  0\. Setup      Repo, Docker Compose   Services start;      End-to-end
                 skeleton, sample       replay produces Zeek \'hello flow\'
                 PCAPs, synthetic       logs.                reaches the
                 generator v1.                               dashboard.

  1\. Core       Normaliser, Redis      FR-01 to FR-04,      Live replay shows
  pipeline       Streams, sketches,     FR-10, FR-11, FR-13, scan and flood
                 scan/DDoS/SYN/DNS      FR-14, FR-40 to      alerts with
                 detectors, alert       FR-43.               evidence.
                 schema, API, basic                          
                 dashboard.                                  

  2\. Trust      Passivity panel,       FR-30 to FR-32.      TX = 0 shown
  features       outbound self-test,                         live; injected
                 Visibility Health.                          loss changes
                                                             health and
                                                             confidence.

  3\.            C2 beaconing,          FR-16, FR-19 to      Multi-stage
  Intelligence   behavioural ML,        FR-22, FR-24.        scenario yields
                 incident engine, SHAP                       one explained
                 explanations,                               incident.
                 timeline.                                   

  4\. Hardening  Hash-chained log, Red  FR-33, FR-52, FR-53, Benchmark report
  and proof      Team scorecard,        FR-17, FR-18.        with measured
                 benchmark harness,                          numbers; demo
                 encrypted-session and                       rehearsed.
                 exfiltration detectors                      
                 if time allows.                             
  ----------------------------------------------------------------------------

16\. Risks and Mitigations

  -----------------------------------------------------------------------
  **Risk**            **Impact**     **Mitigation**
  ------------------- -------------- ------------------------------------
  Python cannot       Benchmark      Partition streams, run multiple
  sustain target      claim fails    workers, vectorise hot paths,
  throughput                         pre-aggregate in Zeek; report only
                                     measured numbers.

  False positives on  Credibility    Peer-group baselines, multi-signal
  benign traffic      loss           fusion, measure alerts/hour on
                                     benign sets.

  Dataset label noise Misleading     Cross-dataset testing; document
  and domain shift    accuracy       known issues; own labelled traffic.

  Overclaiming \'data Judges lose    State clearly that one-way behaviour
  diode\'             trust          is emulated in software; show
                                     attestation evidence.

  Scope creep         Unfinished     Strict P0 first; stretch features
                      core           only after the demo path works.

  Live demo failure   Weak           Deterministic seeded replay and a
                      presentation   pre-recorded fallback.

  Zeek setup          Lost time      Use Docker/Linux; keep PyShark/Scapy
  complexity                         fallback for the basic path.
  -----------------------------------------------------------------------

17\. Success Metrics

-   All P0 requirements pass their acceptance criteria in a recorded
    test run.

-   Each in-scope threat class has at least one reproducible detection
    scenario.

-   Benchmark report with measured throughput and latency percentiles is
    available and reproducible.

-   Zero outbound packets from the sensor across all test runs.

-   100% of alerts carry evidence, an explanation and a valid hash-chain
    link.

-   Red Team scorecard published with honest results, including where
    detection fails.

-   Full demo runs from a single command with no internet access.

18\. Open Questions

-   What are the exact wording and evaluation criteria of the official
    problem statement?

-   Which input will judges expect: PCAP files, live mirrored traffic,
    or flow exports?

-   Is there a required alert format (for example STIX/TAXII) beyond a
    standard JSON schema?

-   What traffic rate must be demonstrated, and on what hardware will
    the demo run?

-   Which datasets, if any, are provided or preferred by the organisers?

Appendix A. Glossary

  -----------------------------------------------------------------------
  **Term**          **Meaning**
  ----------------- -----------------------------------------------------
  Data diode        Hardware/network device that allows data to travel in
                    one direction only.

  PCAP              Packet capture file format.

  NetFlow / IPFIX   Flow-record export formats summarising network
                    conversations.

  C2                Command and control: channel between malware and its
                    operator.

  DGA               Domain generation algorithm: malware technique that
                    generates many domain names.

  JA3 / JA4         Fingerprints of TLS client handshake characteristics.

  HyperLogLog       Probabilistic data structure for counting distinct
                    items in small fixed memory.

  Count-Min Sketch  Probabilistic structure for estimating item
                    frequencies.

  EWMA / CUSUM      Statistical methods for tracking baselines and
                    detecting shifts.

  SHAP              Method for attributing a model\'s prediction to its
                    input features.

  MITRE ATT&CK      Public knowledge base of adversary tactics and
                    techniques.

  Merkle root       Single hash summarising a set of hashed records.
  -----------------------------------------------------------------------
