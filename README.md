<<<<<<< HEAD
# ⚔️ Cybersecurity Decision Agent — MITRE ATT&CK Adversarial Modeling

A game-theoretic cybersecurity decision agent that models attacker-defender interactions within the **MITRE ATT&CK** framework. Combines **Bayesian inference**, **game theory**, and **reinforcement learning** to predict adversary behavior and recommend optimal defensive actions in real time.

![Simulation Mode](https://img.shields.io/badge/Mode-Simulation-blue) ![Live IOC](https://img.shields.io/badge/Mode-Live%20IOC-green) ![JavaScript](https://img.shields.io/badge/Built%20with-JavaScript-yellow) ![License](https://img.shields.io/badge/License-MIT-brightgreen)

---

## 🎯 What It Does

| Input | Process | Output |
|-------|---------|--------|
| IOCs (IPs, domains, hashes, URLs) | CTI enrichment → ATT&CK mapping → Bayesian belief update → Game theory | Predicted next techniques + optimal defender actions |
| Simulated attacker archetype | Sequential Bayesian game with Q-learning | Kill chain visualization, payoff heatmaps, policy convergence |

### Two Operating Modes

- **🎮 Simulation Mode** — Run synthetic adversarial games against 4 attacker archetypes (Script Kiddie, Organized Crime, APT/State Actor, Insider Threat). Train a Q-learning defender agent over 100+ episodes.
- **📡 Live IOC Analysis** — Submit real-world IOCs, query threat intelligence feeds (AlienVault OTX, VirusTotal, AbuseIPDB), map to ATT&CK techniques, and get real-time predictions and defense recommendations.

---

## 🧠 Core Architecture

```
IOC / Simulation → Bayesian Belief Engine → Game-Theoretic Optimizer → RL Policy Agent
                        ↓                          ↓                        ↓
                  Attacker Type              Payoff Matrix            Q-Learning
                  Inference                  + Nash Equilibrium       Defender Policy
```

**Key Components:**

- **Bayesian Engine** — Maintains posterior P(θ|observations) over 4 adversary types using Bayes' theorem. Entropy-based uncertainty tracking.
- **Game Engine** — Computes defender/attacker utility matrices over ATT&CK techniques × 15 defender actions. Solves for mixed-strategy Nash equilibrium via fictitious play.
- **RL Agent** — Tabular Q-learning with ε-greedy exploration. Discretized state space: tactic phase × belief bucket × severity × criticality × last action (7,560 states).
- **CTI Integration** — Express.js backend proxies AlienVault OTX, VirusTotal v3, and AbuseIPDB APIs. IOC-to-ATT&CK mapping via 23 abuse categories + 7 contextual inference rules.

---

## 🚀 Quick Start

```bash
# 1. Clone and install
git clone https://github.com/your-username/cybersecurity-decision-agent.git
cd cybersecurity-decision-agent
npm install

# 2. Configure API keys (optional, for Live IOC mode)
cp .env.example .env
# Edit .env with your free API keys:
#   OTX_API_KEY     → https://otx.alienvault.com/
#   VT_API_KEY      → https://www.virustotal.com/
#   ABUSEIPDB_API_KEY → https://www.abuseipdb.com/

# 3. Start server
node server.js

# 4. Open http://localhost:3000
```

---

## 📊 Features

| Feature | Description |
|---------|-------------|
| **Kill Chain Visualization** | Real-time ATT&CK tactic phase progression with detection highlighting |
| **Belief State Bars** | Animated posterior distribution over attacker archetypes |
| **Next Technique Predictions** | Top-5 predicted adversary techniques with confidence scores |
| **Defensive Action Ranking** | Game-theoretic expected utility ranking of 15 defender actions |
| **Payoff Heatmap** | Color-coded technique × action utility matrix |
| **RL Training Chart** | Episode reward convergence with smoothed trend line |
| **IOC Timeline** | Per-indicator analysis history with threat scores and ATT&CK mappings |
| **CTI Enrichment Cards** | Per-feed results from OTX, VirusTotal, AbuseIPDB |

---

## 🏗️ Project Structure

```
├── server.js                    # Express backend (CTI API proxy)
├── index.html                   # Main UI shell (dual-mode tabs)
├── index.css                    # Dark theme design system
├── .env.example                 # API key template
├── js/
│   ├── app.js                   # UI controller (simulation + live mode)
│   ├── data/
│   │   ├── mitre-catalog.js     # 41 techniques, 14 tactics, transition matrix
│   │   ├── attacker-profiles.js # 4 adversary archetypes
│   │   └── defender-actions.js  # 15 defender actions with costs/effectiveness
│   └── engine/
│       ├── bayesian-engine.js   # Bayesian belief updating
│       ├── game-engine.js       # Payoff matrices + fictitious play
│       ├── rl-agent.js          # Q-learning defender agent
│       ├── simulation.js        # Sequential game loop
│       ├── cti-manager.js       # CTI feed client
│       ├── ioc-mapper.js        # IOC → ATT&CK technique mapping
│       └── live-monitor.js      # Live analysis session orchestrator
```

---

## 📐 Mathematical Foundation

**State Space:** S = (T, B, D) where T = technique node, B = belief distribution, D = defender posture

**Bayesian Update:** P(θ | t) ∝ P(t | θ) · P(θ)

**Defender Utility:** U_D = w₁·P(detect) + w₂·P(prevent) − w₃·cost − w₄·disruption

**Q-Learning:** Q(s,a) ← Q(s,a) + α[r + γ·max Q(s',a') − Q(s,a)]

**Nash Equilibrium:** Approximated via fictitious play (1000 iterations)

---

## 📚 Built For

Master's thesis research in cybersecurity / game theory. Combines formal mathematical modeling with practical threat intelligence integration.

**Keywords:** Game Theory, Bayesian Games, Reinforcement Learning, MITRE ATT&CK, Cyber Threat Intelligence, Q-Learning, Adversarial Decision-Making

---

## 📄 License

MIT License — free for academic and research use.
=======
# A-Game-Theoretic-Approach-to-Adaptive-Cyber-Defense
A game-theoretic cybersecurity decision agent that models attacker-defender interactions within the MITRE ATT&amp;CK framework. Combines Bayesian inference, game theory, and reinforcement learning to predict adversary behavior and recommend optimal defensive actions in real time.
>>>>>>> 4ae31958b78f7102d472ece032527d6d975222b9
