# CatNet – Reconnaissance Pipeline Specification

This document defines the internal execution pipeline of CatNet.
It specifies **what happens**, **in what order**, and **under what conditions**.
No implementation details are included here.

CatNet follows a strict, evidence-driven model:
actions are performed only when justified by prior observations.

---

## Global Execution Flow

1. Target validation
2. Stage 1: Host Discovery
3. Stage 2: Initial Port Scan
4. Stage 3: Conditional Service Detection
5. Stage 4: Protocol-Specific Enumeration
6. Stage 5: Host Classification
7. Stage 6: Reporting

Each stage:
- Consumes structured input
- Produces structured output
- Explicitly records skipped actions and uncertainty

No stage may bypass another without justification.

---

## Stage 0: Target Validation

### Input
- User-supplied target (IP, CIDR)

### Behavior
- Validate target format
- Determine whether the target is a local network
- Refuse unsupported targets gracefully

### Output
- Validated target
- Scan context (local / non-local)

### Notes
- CatNet does not promise full compatibility with non-local targets
- Validation failure halts execution

---

## Stage 1: Host Discovery

### Purpose
Identify responsive hosts on the local network without assuming completeness.

### Input
- Validated local network range

### Behavior
- Perform ARP-based host discovery only
- Do not infer host type or operating system
- Do not assume silence implies absence

### Output
For each responsive host:
- IP address
- MAC address (if available)
- Discovery method used

### Explicit Statements
- Responsive hosts are not equal to all connected devices
- Silent hosts are not classified as offline

### Proceed Conditions
- Proceed to Stage 2 only for responsive hosts
- If no hosts respond, continue to reporting with explicit limitations

---

## Stage 2: Initial Port Scan

### Purpose
Determine whether a host exposes any TCP surface worth further inspection.

### Input
- List of responsive hosts from Stage 1

### Behavior
- Scan only top TCP ports
- Scan only hosts confirmed responsive
- Treat host reachability as already established

### Output
For each host:
- List of open TCP ports (may be empty)

### Classification Rules
- Hosts with zero open ports are marked as:
  “Silent / Firewalled Host (Preliminary)”

### Proceed Conditions
- Proceed to Stage 3 only if one or more open ports are detected
- Hosts with no open ports are excluded from further probing

---

## Stage 3: Conditional Service Detection

### Purpose
Refine understanding of exposed services without expanding scan scope.

### Input
- Hosts with open ports from Stage 2

### Behavior
- Perform service/version detection only on known open ports
- Do not scan closed or filtered ports
- Accept incomplete or ambiguous results

### Output
For each open port:
- Service name (if detected)
- Version information (if available)
- CPE information (if available)

### Explicit Limitations
- Absence of version data is recorded as uncertainty
- Service detection failure is not treated as negative evidence

### Proceed Conditions
- Proceed to Stage 4 only if a recognized protocol is identified

---

## Stage 4: Protocol-Specific Enumeration

### Purpose
Gather protocol-level metadata using targeted, relevant scripts only.

### Input
- Detected services and protocols from Stage 3

### Behavior
- Run scripts only when the corresponding protocol is confirmed
- Do not perform blanket or speculative script execution

### Protocol-to-Action Mapping
- HTTP detected → HTTP metadata scripts
- SMB detected → SMB discovery scripts
- SSL/TLS detected → Certificate inspection
- RPC detected → RPC metadata queries

### Output
- Protocol-specific metadata
- Script execution success or failure

### Explicit Skips
- Scripts for absent protocols are explicitly marked as skipped

---

## Stage 5: Host Classification Engine

### Purpose
Infer host type using observed evidence without claiming certainty.

### Input
- Aggregated evidence from all previous stages

### Behavior
- Apply rule-based classification
- Weigh evidence signals
- Resolve conflicting indicators conservatively

### Possible Classifications
- Router / Gateway
- Windows Host
- Linux Host
- Embedded / IoT Device
- Silent / Firewalled Host
- Unknown

### Confidence Levels
- Low
- Medium
- High

### Requirements
- Every classification must list supporting evidence
- Low-confidence results must remain explicitly tentative

---

## Stage 6: Reporting

### Purpose
Present findings clearly, honestly, and without exaggeration.

### Report Contents
For each host:
- Discovery status
- Open ports
- Detected services
- Protocol metadata (if any)
- Classification and confidence
- Explicit limitations and skipped actions

### Global Report Includes
- Scan scope summary
- Methods used
- User-forced overrides (if any)
- Known blind spots

### Reporting Rules
- Silence is never reported as absence
- Skipped actions are always disclosed
- Uncertainty is stated explicitly

---

## Evidence Rules

- Only directly observed data counts as evidence
- Inference requires multiple supporting signals
- Absence of data is recorded, not interpreted
- User-forced actions downgrade confidence

---

## Failure and Uncertainty Handling

- Timeouts are recorded per host
- Partial scan results are preserved
- Script failures are not silently ignored
- Errors do not halt unrelated stages

CatNet prioritizes transparency over completeness.


