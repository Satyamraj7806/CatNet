# CatNet

CatNet is an evidence-driven network reconnaissance assistant for local networks.

It uses Nmap as an observation engine — not an attack tool — and performs staged, protocol-aware enumeration without making assumptions, over-scanning, or hiding uncertainty.

CatNet is designed to **think before it scans**.

---

## What CatNet Is

CatNet performs **safe, explainable network enumeration** by:

- Discovering hosts using minimal, local-network techniques
- Escalating scans only when prior evidence justifies it
- Running protocol-specific enumeration instead of blanket scans
- Separating **observed facts** from **inferred conclusions**
- Reporting confidence levels and explicit limitations

CatNet does **not** attempt to replace Nmap.  
It acts as a reasoning layer on top of it.

---

## What CatNet Is NOT

CatNet will **never**:

- Exploit vulnerabilities
- Brute-force services
- Perform vulnerability scanning
- Claim full device discovery
- Pretend certainty where none exists
- Run aggressive scans by default

This is a reconnaissance assistant, not a hacking framework.

---

## Design Philosophy

CatNet is built around these principles:

- **Logic before aggression**
- **Evidence before escalation**
- **Protocol awareness**
- **Explainable decisions**
- **Honest uncertainty**

Silence does not mean “down”.  
Unknown does not mean “vulnerable”.

---

## Intended Use

CatNet is intended for:

- Learning and practicing responsible network reconnaissance
- Understanding how scan results should be interpreted
- Building disciplined enumeration habits
- Educational and defensive analysis on networks you own or are authorized to assess

---

## Status

CatNet is under active development.

The current focus is on:
- Clear scan staging
- Transparent decision-making
- Structured, honest reporting

Features will be added only if they align with the core philosophy.

---

## Disclaimer

CatNet must only be used on networks you own or have explicit permission to analyze.

The author assumes no responsibility for misuse.

