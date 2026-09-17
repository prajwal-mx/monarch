# MONARCH: Open-Source Supply Chain Risk & Blast-Radius Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-37%20passed-brightgreen.svg)](tests/)
[![Architecture](https://img.shields.io/badge/engine-CSR%20Graph%20%7C%20Dominator%20Tree-orange.svg)](#architecture)
[![Standard](https://img.shields.io/badge/standards-OpenVEX%20%7C%20CycloneDX-informational.svg)](#standards--integrations)

**MONARCH** is a proactive graph-theoretic governance engine designed to detect, quantify, and remediate supply chain risks in deeply nested open-source dependency trees before vulnerabilities reach production.

---

## The Problem

Modern software applications are assembled from hundreds of third-party packages, where **over 85% of codebase volume consists of transitive dependencies**. A single compromise, unreviewed maintainer transfer, or malicious hook in an obscure 10-line leaf utility triggers a cascading ripple effect across thousands of downstream systems (e.g., `event-stream`, `xz-utils`, `ua-parser-js`).

Existing ecosystem tooling (`npm audit`, basic CVE lists) suffers from three structural flaws:
1. **Alert Fatigue & Noise**: Flat list scanners report every matching CVE without verifying reachability. Over **80% of security alerts are false alarms** on unreachable code that is never imported or executed.
2. **Lagging & Reactive**: Scanners only flag vulnerabilities *after* a CVE is formally indexed in the NVD—often days or weeks after active exploitation has begun.
3. **Destructive Remediation**: Automated PR bots naively suggest bumping every affected package, causing breaking API changes and build failures instead of identifying the exact structural choke points.

---

## Core Capabilities

### 1. In-Memory Graph Engine & Blast-Radius Traversal
- Ingests `package-lock.json`, Yarn lockfiles, and SBOM manifests into a memory-efficient Compressed Sparse Row (CSR) graph.
- Condenses dependency cycles using **Tarjan's Strongly Connected Components (SCC)** algorithm to produce provably acyclic DAGs.
- Evaluates reverse blast-radius reachability across 100,000+ dependency edges in **under 50 milliseconds**.

### 2. Multi-Factor Consequence Scoring $C(v)$
Computes a continuous 0–100 consequence score reflecting real structural impact:
- **Reverse Reachability Depth**: Quantifies downstream applications and modules exposed to a compromised package.
- **Geometric Download Decay** ($\gamma = 0.8$): Weights packages closer to the root application higher than deeply decoupled leaf utilities.
- **Betweenness Centrality**: Pinpoints transit hubs that act as cross-cutting bridges between disparate subsystems.

### 3. Publish-Time Fragility & Custody Anomaly Detection $F(v)$
Monitors real-time supply chain custody signals prior to official CVE disclosure:
- **Lifecycle Hook Execution**: Detects suspicious `preinstall`, `install`, and `postinstall` shell script activity.
- **Maintainer Custody Churn**: Flags sudden transfers to new unverified maintainers after dormant periods.
- **Release Bursts & Drift**: Identifies unexpected version cadence bursts and repository origin mismatches.

### 4. Tier-2 AST Call-Site Reachability
- Performs static AST analysis over application source files (`.js`, `.ts`) to verify if a flagged package symbol or function is actually imported and executed in user code paths.
- Automatically suppresses non-exploitable transitive CVEs and exports compliance-ready **OpenVEX** statements (`not_affected`, `code_not_reachable`).

### 5. Dominator Tree Remediation Solver
- Computes the immediate dominator tree (`idom`) from the root project using the **Lengauer-Tarjan** algorithm.
- Formulates remediation as a submodular optimization problem, discovering the provably minimal set of direct dependency interventions (`PIN`, `UPGRADE`, `OVERRIDE`) to neutralize downstream risk without breaking API contracts.

### 6. Interactive Web Dashboard & Cytoscape Graph Explorer
- **Live Lockfile Auditing**: Drag-and-drop any lockfile for instant risk breakdown and blast-radius visualization.
- **Interactive Graph Visualizer**: Inspect direct and transitive dependency trees, attack paths, and critical choke points.
- **Historical Backtesting**: Benchmark detection heuristics against documented incidents (`xz-utils`, `event-stream`, `ua-parser-js`).
- **Remediation Export**: One-click action plan generator providing copy-paste lockfile overrides.

---

## Architecture

```
                               ┌───────────────────────────┐
                               │  Lockfiles / SBOM Inputs  │
                               │  (npm, yarn, CycloneDX)   │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │     In-Memory CSR Graph   │
                               │  • Tarjan SCC Condensation│
                               │  • Blast-Radius Traversal │
                               └─────────────┬─────────────┘
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      ▼                                             ▼
        ┌───────────────────────────┐                 ┌───────────────────────────┐
        │  Consequence Engine C(v)  │                 │   Fragility Engine F(v)   │
        │  • Reverse Reachability   │                 │   • Lifecycle Hooks       │
        │  • Betweenness Centrality │                 │   • Maintainer Churn      │
        │  • Download Depth Decay   │                 │   • Release Anomalies     │
        └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                      │                                             │
                      └──────────────────────┬──────────────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │    Composite Risk Score   │
                               │     R(v) = C(v) × F(v)    │
                               └─────────────┬─────────────┘
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      ▼                                             ▼
        ┌───────────────────────────┐                 ┌───────────────────────────┐
        │    AST Call-Site Pruning  │                 │   Dominator Tree Solver   │
        │    • Import & Call Search │                 │   • Lengauer-Tarjan idom  │
        │    • OpenVEX Generation   │                 │   • Minimal Choke Points  │
        └───────────────────────────┘                 └───────────────────────────┘
```

---

## Getting Started

### Prerequisites
- **Python**: 3.11 or later
- **Git**

### Installation

```bash
# Clone the repository
git clone https://github.com/prajwal-mx/monarch.git
cd monarch

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Web Dashboard

```bash
python3 -m monarch.web.app
```
Once launched, open **`http://127.0.0.1:5000`** in your browser to access the dashboard.

### CLI Usage

```bash
# Scan a package-lock.json file
python3 monarch_cli.py scan package-lock.json

# Analyze blast-radius of a specific package
python3 monarch_cli.py blast-radius --package colors --version 1.4.0

# Compute minimal dominator choke points
python3 monarch_cli.py solve package-lock.json

# Generate OpenVEX compliance statement
python3 monarch_cli.py vex --lockfile package-lock.json --src ./src
```

### Running the Test Suite

```bash
pytest
```
*Executes all 37 comprehensive unit and integration tests covering graph algorithms, scoring models, AST reachability, and remediation solver.*

---

## Directory Layout

```
.
├── monarch/
│   ├── common/              # Core data models, SQLite storage layer, resource guards
│   ├── consequence/         # Consequence scoring, reverse reachability, betweenness
│   ├── customer/            # Lockfile parsers, dominator tree solver, SBOM ingest
│   ├── fragility/           # Maintainer custody tracker, anomaly detection, backtesting
│   ├── graph/               # In-memory CSR graph, Tarjan SCC condensation, epoch versioning
│   ├── ingestion/           # Registry stream watcher, package hydrator, CAS cache
│   ├── reachability/        # AST call-site reachability, symbol resolution, OpenVEX emitter
│   ├── web/                 # Flask application, REST API endpoints, static assets & UI
│   └── cli/                 # CLI entry points and policy gate evaluation
├── tests/                   # 37 unit and integration tests
├── requirements.txt         # Core dependencies (Flask, NetworkX, etc.)
├── LICENSE                  # MIT License
└── README.md                # System documentation
```

---

## Standards & Integrations

- **OpenVEX**: Outputs machine-readable VEX assertions (`not_affected`, `in_vulnerable_code_branch`).
- **CycloneDX**: Native parsing and enrichment for CycloneDX JSON Software Bill of Materials (SBOM).
- **CI/CD Gating**: Exit code enforcement for pre-merge PR blocking based on configurable blast-radius thresholds.

---

## License

This project is open-source and licensed under the [MIT License](LICENSE).
