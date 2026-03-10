# SPEC.md — Project Specification

> **Status**: `FINALIZED`

## Vision

Build a production-grade, academically rigorous cybersecurity decision agent that models attacker-defender interactions as a sequential Bayesian game within the MITRE ATT&CK framework. The system ingests real-time threat intelligence, identifies adversary archetypes via Bayesian inference, computes optimal defense strategies via game theory, and learns adaptive policies via reinforcement learning. Serves both as a thesis contribution to the game-theoretic cybersecurity literature and as a practical tool for SOC analysts performing real-time IOC triage.

## Goals

1. **Academically defensible implementation** — Mathematical framework (Bayesian games, Q-learning, fictitious play) grounded in published literature, with empirical validation and statistical analysis
2. **Real-time CTI integration** — Ingest IOCs from AlienVault OTX, VirusTotal, AbuseIPDB; map to ATT&CK; activate game engine
3. **Dual-mode operation** — Simulation mode (synthetic adversarial games) + Live IOC mode (real-world threat analysis)
4. **Extensible architecture** — Clean 4-layer design (Data → Engine → CTI → UI) that supports future enhancements (DQN, STIX/TAXII, SIEM integration)
5. **Professional-quality presentation** — Interactive dashboard suitable for thesis defense demos and SOC analyst evaluation

## Non-Goals (Out of Scope)

- Production SIEM/SOAR integration (Splunk, QRadar, Elastic)
- Multi-user authentication or role-based access
- Mobile-responsive UI
- Real network traffic ingestion or packet analysis
- Cloud deployment / containerization (Docker, K8s)
- Full ATT&CK matrix coverage (~200 techniques) — using curated 41-technique subset
- Adversarial ML / model robustness testing
- Compliance framework mapping (NIST, ISO 27001)

## Users

1. **Thesis committee / academic reviewers** — evaluate mathematical rigor, experimental methodology, and contribution novelty
2. **SOC analysts** — use Live IOC mode to triage indicators, understand threat context via ATT&CK mapping, and receive prioritized defense recommendations
3. **Cybersecurity students/researchers** — learn game-theoretic defense concepts through interactive simulation

## Constraints

- **Technology**: Pure JavaScript (no ML frameworks), Node.js backend, browser-native frontend
- **APIs**: Free-tier CTI feeds (rate-limited)
- **Timeline**: Thesis submission deadline-driven
- **Data**: ATT&CK technique catalog limited to 41 representative techniques; attacker profiles heuristic-based

## Success Criteria

- [x] Bayesian belief converges to true attacker type within 3–6 observations
- [x] RL agent shows monotonically increasing reward over 100 training episodes
- [x] Game-theoretic action ranking produces context-appropriate recommendations
- [x] Live IOC mode successfully queries 3 CTI feeds and maps IOCs to ATT&CK
- [x] Dual-mode UI renders correctly with zero JavaScript errors
- [ ] Automated test suite with ≥80% engine coverage
- [ ] Thesis report passes committee review
- [ ] System handles edge cases gracefully (empty feeds, malformed IOCs, API timeouts)
