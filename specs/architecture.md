# CatNet – Internal Architecture Specification

This document defines the internal architecture of CatNet.
It specifies **logical components**, **responsibilities**, and **data flow rules**.

This is a design document.
No implementation details, filenames, or code structures are defined here.

---

## Architectural Philosophy

CatNet is designed as a **reasoning system**, not a scan launcher.

Core principles:
- Separation of concerns
- Evidence-driven escalation
- Explicit data ownership
- No implicit side effects
- No hidden decision-making

Each component has a single responsibility.
No component is allowed to “think” outside its scope.

---

## High-Level Architecture Overview

CatNet is composed of the following logical components:

1. CLI Interface
2. Scan Orchestrator
3. Stage Engine
4. Nmap Adapter
5. Evidence Store
6. Host Classification Engine
7. Reporting Engine

Control flow is strictly top-down.
No circular dependencies are permitted.

---

## Component Definitions

### 1. CLI Interface

#### Responsibility
- Accept user input
- Parse targets and flags
- Capture user intent (default vs overrides)

#### Owns
- User-provided parameters
- Execution mode selection

#### Does NOT Own
- Scan logic
- Escalation decisions
- Evidence interpretation

#### Produces
- Execution configuration object

#### Notes
The CLI interface is passive.
It never initiates scans or interprets results.

---

### 2. Scan Orchestrator

#### Responsibility
- Control the overall execution flow
- Invoke pipeline stages in correct order
- Enforce escalation rules defined in the pipeline

#### Owns
- Stage sequencing
- Execution lifecycle

#### Does NOT Own
- Nmap invocation details
- Evidence interpretation
- Reporting logic

#### Produces
- Stage execution requests
- Final scan state

#### Notes
The orchestrator enforces discipline.
It does not make analytical decisions.

---

### 3. Stage Engine

#### Responsibility
- Execute individual pipeline stages
- Apply stage-specific preconditions
- Handle stage-level failures

#### Owns
- Stage execution rules
- Stage input/output validation

#### Does NOT Own
- Global execution flow
- Evidence interpretation beyond stage scope

#### Produces
- Structured stage outputs
- Stage-level uncertainty markers

---

### 4. Nmap Adapter

#### Responsibility
- Interface with Nmap via subprocess
- Execute scans as requested
- Produce raw machine-readable output

#### Owns
- Command execution
- Output capture
- Error and timeout handling

#### Does NOT Own
- Scan logic decisions
- Result interpretation
- Evidence classification

#### Produces
- Raw scan results
- Execution metadata

#### Notes
This component is intentionally “dumb”.
It does not understand what the data means.

---

### 5. Evidence Store

#### Responsibility
- Maintain structured evidence per host
- Record observations, uncertainties, and skips
- Preserve raw and derived facts

#### Owns
- Host records
- Evidence ledger
- Confidence modifiers

#### Does NOT Own
- Scan execution
- Classification rules
- Reporting format

#### Produces
- Aggregated host evidence

#### Notes
The Evidence Store is the single source of truth.
All higher-level reasoning depends on it.

---

### 6. Host Classification Engine

#### Responsibility
- Infer host type using rule-based logic
- Assign confidence levels
- Resolve conflicting indicators conservatively

#### Owns
- Classification rules
- Confidence scoring logic

#### Does NOT Own
- Raw scan data
- Scan execution
- Reporting presentation

#### Produces
- Host classification
- Confidence level
- Explanation of reasoning

#### Notes
Classification is inference, not detection.
Uncertainty is preserved explicitly.

---

### 7. Reporting Engine

#### Responsibility
- Present findings to the user
- Clearly separate facts from inference
- Explicitly state limitations and skips

#### Owns
- Output structure
- Messaging clarity
- Disclosure of uncertainty

#### Does NOT Own
- Scan decisions
- Evidence generation
- Classification logic

#### Produces
- Terminal-readable final report

---

## Data Ownership Rules

- Host objects are created during Stage 1
- Evidence Store is the only component allowed to mutate host records
- All other components interact with host data via controlled interfaces
- No component may silently alter host state

---

## Control Flow Rules

- CLI Interface → Scan Orchestrator
- Scan Orchestrator → Stage Engine
- Stage Engine → Nmap Adapter (indirectly)
- Stage outputs → Evidence Store
- Evidence Store → Classification Engine
- Evidence Store + Classification → Reporting Engine

No reverse calls are allowed.

---

## Override Handling Rules

- User overrides are recorded explicitly
- Forced actions downgrade confidence
- Overrides never suppress disclosure
- Hard exclusions (exploitation, brute-force) cannot be overridden

---

## Forbidden Couplings

The following interactions are explicitly forbidden:

- CLI Interface invoking Nmap directly
- Classification Engine triggering scans
- Reporting Engine influencing scan scope
- Nmap Adapter interpreting results
- Stage Engine modifying classification outcomes

Violation of these rules indicates a design failure.

---

## Architectural Guarantees

This architecture guarantees that:

- No scan occurs without justification
- No conclusion is made without evidence
- No uncertainty is hidden
- User intent is preserved and disclosed
- CatNet remains auditable and explainable

CatNet prioritizes correctness and transparency over speed or coverage.

