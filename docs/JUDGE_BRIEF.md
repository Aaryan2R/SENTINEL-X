# SENTINEL-X judge brief

## The 90-second story

**Problem (15 seconds):** A conventional IDS expects a two-way network. In a
data-diode or receive-only environment, that assumption is dangerous and
unprovable. Operators also need to know when packet loss makes an alert less
trustworthy.

**Innovation (20 seconds):** SENTINEL-X is metadata-only and receive-only by
design. It exposes passivity status, computes a visibility-health modifier,
and links every alert to evidence and its predecessor with a SHA-256 chain.

**Proof (35 seconds):**

1. Run `.\scripts\demo.ps1 -InstallFrontend`.
2. Show `PASSIVITY EMULATED` on Windows, or `PASSIVITY VERIFIED` with a Linux
   capture interface.
3. Reset and run the benign scenario: zero alerts.
4. Run the port-scan scenario: open the alert and show score, ATT&CK technique,
   detector version, contributions, `evidence_hash`, and `prev_hash`.
5. Run the SYN-flood scenario and point to the different detector and evidence.
6. Click `VERIFY CHAIN` and show `EVIDENCE CHAIN VALID`.

**Close (20 seconds):** The prototype is honest about the boundary: Windows
uses software emulation, Linux can read the kernel TX counter, and production
deployment adds the tc/nftables and hardware-diode controls. The same
detector contracts and reproducible replay are ready for that hardening.

## Why it stands apart

- **Trust is a feature:** passivity and visibility are shown beside detections,
  not buried in deployment notes.
- **Evidence is inspectable:** every alert explains its score and carries a
  verifiable predecessor hash.
- **No black-box demo theatre:** benign traffic is a required regression, and
  measured results are generated on the actual presentation machine.
- **Offline by design:** the replay and local dashboard need no reputation API,
  cloud model, or internet connection.

## Submission claims

Use the measured `docs/evaluation/latest.json` output from the presentation
machine. Do not copy latency or throughput values from another machine. Keep
the software-emulation limitation visible in the slide deck and demo.
