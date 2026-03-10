# DECISIONS.md — Architecture Decision Records

> Log of significant technical decisions.

| Date | Decision | Context | Alternatives Considered |
|------|----------|---------|------------------------|
| 2026-03-03 | Pure JavaScript, no ML frameworks | Keep dependencies minimal, run in browser | TensorFlow.js, PyTorch (Python backend) |
| 2026-03-03 | Tabular Q-learning over DQN | 7,560-state space is tractable; transparency over performance | DQN, PPO, A2C |
| 2026-03-03 | Fictitious play for Nash equilibrium | Simple, convergent for finite games; no LP solver needed | Lemke-Howson, linear programming, support enumeration |
| 2026-03-03 | 41-technique ATT&CK subset | Covers all 14 tactics with manageable state space | Full Enterprise matrix (~200 techniques) |
| 2026-03-03 | Express.js backend proxy | Browser CORS prevents direct CTI API calls | CORS proxy service, serverless functions |
| 2026-03-03 | node-fetch v2 (CommonJS) | Server uses require(); v3 is ESM-only | Axios, native fetch (Node 18+) |
| 2026-03-03 | Heuristic attacker profiles | No public dataset of attacker-type→technique distributions | ML clustering on MITRE STIX data |
