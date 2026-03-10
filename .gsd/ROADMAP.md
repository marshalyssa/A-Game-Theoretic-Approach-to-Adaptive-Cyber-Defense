# ROADMAP.md

> **Current Phase**: Phase 1 completed (v1.0 delivered)
> **Milestone**: v2.0 — Hardening & Thesis Defense

## Completed (v1.0)

- [x] ATT&CK data model (41 techniques, 14 tactics, transition matrix)
- [x] Bayesian inference engine (attacker-type identification)
- [x] Game-theoretic engine (payoff matrices, fictitious play Nash equilibrium)
- [x] Q-learning defender agent (ε-greedy, 7,560+state Q-table)
- [x] Simulation engine (sequential imperfect-information game loop)
- [x] CTI integration (OTX, VirusTotal, AbuseIPDB via Express proxy)
- [x] IOC-to-ATT&CK mapper (23 categories + 7 contextual rules)
- [x] Live IOC analysis mode (enrichment → mapping → belief → prediction)
- [x] Dual-mode web dashboard (Simulation + Live IOC tabs)
- [x] Thesis report (9 chapters, ~6,500 words)

## Phases

### Phase 1: Testing & Quality Assurance
**Status**: ⬜ Not Started
**Objective**: Add automated tests for all engine modules to ensure correctness and prevent regressions
**Deliverables**:
- Unit tests for bayesian-engine, game-engine, rl-agent
- Integration tests for simulation pipeline
- IOC mapper edge case tests
- Server API route tests

### Phase 2: Edge Case Hardening
**Status**: ✅ Complete
**Objective**: Handle malformed inputs, API failures, and boundary conditions gracefully
**Deliverables**:
- Input validation and sanitization (IOC input, config values) ✔
- API timeout handling with retries ✔
- Rate limiting on proxy endpoints ✔
- Error boundary UI states ✔

### Phase 3: Experiment Automation
**Status**: ⬜ Not Started
**Objective**: Automate the experimental evaluation pipeline for thesis Chapter 6–7
**Deliverables**:
- Batch simulation runner (all 4 attacker types × 5 detection levels)
- Statistical significance testing (confidence intervals, p-values)
- CSV/JSON export of experiment results
- Automated chart generation (convergence plots, ablation tables)

### Phase 4: Thesis Defense Preparation
**Status**: ⬜ Not Started
**Objective**: Polish the system for live demonstration during thesis defense
**Deliverables**:
- Pre-loaded demo scenarios (known malicious IOCs for compelling demos)
- Presentation mode (larger fonts, guided walkthrough)
- Record demo video as backup
- Final thesis report polish and committee feedback integration
