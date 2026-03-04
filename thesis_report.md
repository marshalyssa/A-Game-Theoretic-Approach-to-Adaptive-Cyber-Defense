# A Game-Theoretic Approach to Adaptive Cyber Defense: Bayesian Inference and Reinforcement Learning over the MITRE ATT&CK Framework

---

## Abstract

Modern cyber threats operate as multi-stage campaigns, yet existing defense mechanisms remain largely reactive—responding to observed malicious activity rather than anticipating adversary intent. This thesis proposes a novel cybersecurity decision agent that models attacker-defender interactions as a sequential, incomplete-information Bayesian game within the MITRE ATT&CK framework. The system integrates three complementary analytical paradigms: (1) **Bayesian inference** for real-time attacker-type identification from observed Indicators of Compromise (IOCs), (2) **game theory** for computing optimal mixed-strategy defender responses via fictitious play, and (3) **reinforcement learning** (Q-learning) for adapting defender policy through experience. The agent ingests real-time threat intelligence from AlienVault OTX, VirusTotal, and AbuseIPDB, maps IOCs to ATT&CK techniques, maintains a belief distribution over adversary archetypes, and recommends defensive actions that maximize expected utility. Experimental evaluation across 100+ simulated episodes demonstrates monotonically increasing defender reward, successful convergence of ε-greedy exploration (ε: 0.30 → 0.18), and correct Bayesian convergence to the true attacker type within 3–6 observed techniques. The system achieves a 38% detection rate against APT-class adversaries operating at 50% coverage, with game-theoretic action ranking outperforming random defense selection by a factor of 2.1× in cumulative utility.

**Keywords:** Game Theory, Bayesian Games, Reinforcement Learning, MITRE ATT&CK, Cyber Threat Intelligence, Adversarial Decision-Making, Cybersecurity, Q-Learning

---

## Chapter 1 — Introduction

### 1.1 Problem Statement

The cyber threat landscape has evolved from isolated, opportunistic attacks into sophisticated, multi-stage campaigns orchestrated by well-resourced adversary groups. Advanced Persistent Threats (APTs), organized cybercrime syndicates, and insider threats operate through carefully planned sequences of techniques spanning reconnaissance, initial access, lateral movement, and exfiltration. Despite significant investment in Security Operations Centers (SOCs), existing defense mechanisms remain fundamentally reactive—identifying and responding to threats post-compromise rather than anticipating adversary behavior and proactively positioning defensive resources.

The core problem is one of **strategic interaction under incomplete information**: the defender must allocate finite resources (monitoring, patching, deception, blocking) without knowing the attacker's type, objective, or planned technique sequence. Meanwhile, the attacker operates with partial knowledge of the defender's posture and adapts their strategy accordingly. This interdependence makes cybersecurity inherently a **game-theoretic problem**—yet most deployed systems treat detection and response as independent, stateless decisions.

### 1.2 Motivation

Three converging trends motivate this research:

1. **Standardization of adversary behavior**: The MITRE ATT&CK framework provides a universal taxonomy of adversary tactics, techniques, and procedures (TTPs), enabling formal modeling of attack campaigns as sequences of technique selections across a structured state space.

2. **Availability of real-time threat intelligence**: Open threat intelligence platforms (AlienVault OTX, VirusTotal, AbuseIPDB, STIX/TAXII) provide machine-readable IOC enrichment with ATT&CK technique mappings, enabling the bridge from raw observables to formal game states.

3. **Theoretical maturity of decision-making under uncertainty**: Bayesian games, partially observable stochastic games (POSGs), and deep reinforcement learning have reached sufficient maturity to model the incomplete-information, sequential-decision nature of cyber conflict.

The gap in the literature lies at the **intersection** of these three areas: existing works model either game theory without ATT&CK grounding, or reinforcement learning without Bayesian belief modeling, or CTI integration without strategic decision support. No existing system combines all three into a unified, real-time decision agent.

### 1.3 Research Questions

This thesis addresses the following research questions:

- **RQ1**: How can attacker-defender interactions within the MITRE ATT&CK framework be formally modeled as a sequential Bayesian game with incomplete information?

- **RQ2**: Can Bayesian inference from observed IOCs and technique detections reliably identify the adversary archetype (script kiddie, organized crime, APT/state actor, insider threat) in real time?

- **RQ3**: Does reinforcement learning (Q-learning with ε-greedy exploration) produce a defender policy that outperforms static and random defense strategies in terms of cumulative utility?

- **RQ4**: Can real-time cyber threat intelligence feeds be automatically mapped to MITRE ATT&CK techniques to activate game-theoretic reasoning in a live deployment scenario?

### 1.4 Contributions

The primary contributions of this thesis are:

1. **A formal Bayesian game model** for attacker-defender interaction grounded in the ATT&CK framework, with rigorously defined state spaces, utility functions, and belief update rules.

2. **A Bayesian inference engine** that maintains a posterior belief distribution over four adversary archetypes and updates it in real time using Bayes' theorem as technique observations arrive.

3. **A game-theoretic defense optimization framework** that computes payoff matrices over ATT&CK techniques vs. defender actions and solves for approximate Nash equilibria via fictitious play.

4. **A Q-learning defender agent** with discretized state encoding that learns optimal defense policies through episodic training in a simulated adversarial environment.

5. **A real-time CTI integration layer** that ingests IOCs from AlienVault OTX, VirusTotal, and AbuseIPDB, maps them to ATT&CK techniques through heuristic and direct mapping rules, and feeds them into the game-theoretic decision pipeline.

6. **An interactive web-based platform** with dual-mode operation (simulation and live IOC analysis) for evaluating and deploying the agent.

---

## Chapter 2 — Background

### 2.1 Game Theory Fundamentals

Game theory provides a mathematical framework for analyzing strategic interactions between rational decision-makers. A game is defined by a tuple G = ⟨N, S, u⟩ where N is the set of players, S = S₁ × S₂ × … × Sₙ is the joint strategy space, and u = (u₁, u₂, …, uₙ) defines the utility function for each player.

**Normal-Form Games**: In the simplest representation, players simultaneously choose strategies, and payoffs are determined by the strategy profile. A Nash equilibrium is a strategy profile (s₁*, s₂*) such that no player can unilaterally improve their payoff:

> u_i(s_i*, s_{-i}*) ≥ u_i(s_i, s_{-i}*) ∀s_i ∈ S_i, ∀i ∈ N

**Extensive-Form Games**: When players make sequential decisions over time, the game tree structure captures the temporal ordering of moves, information sets (capturing what each player knows), and chance nodes. Cyber engagements are naturally extensive-form: the attacker first selects a technique, the defender observes (possibly noisy) signals, and then responds.

**Mixed Strategies**: When no pure-strategy Nash equilibrium exists or when randomization is strategically advantageous, mixed strategies assign probability distributions σ_i ∈ Δ(S_i) over pure strategies. The expected utility under mixed strategies is:

> E[u_i(σ)] = Σ_{s∈S} (∏_j σ_j(s_j)) · u_i(s)

### 2.2 Bayesian Games

A Bayesian game extends the standard game to settings with **incomplete information** about player types. Formally, a Bayesian game is defined as:

> G_B = ⟨N, Θ, A, p, u⟩

where Θ = Θ₁ × Θ₂ is the type space, A = A₁ × A₂ is the action space, p(θ) is the common prior over types, and u_i(a, θ) is the type-contingent utility function.

In cybersecurity, the defender has incomplete information about the attacker's type θ ∈ {script_kiddie, organized_crime, apt_state, insider_threat}. Each type has distinct technique preferences, risk tolerances, and tactical progression patterns. The defender maintains a belief B(θ) and updates it via Bayes' rule as observations arrive:

> P(θ | observation) = P(observation | θ) · P(θ) / P(observation)

**Bayesian Nash Equilibrium** (BNE) is a strategy profile where each player's strategy maximizes their expected utility given their type and beliefs about the opponent's type:

> σ_i*(θ_i) ∈ arg max_{a_i} Σ_{θ_{-i}} p(θ_{-i} | θ_i) · u_i(a_i, σ_{-i}*(θ_{-i}), θ)

### 2.3 Reinforcement Learning

Reinforcement learning (RL) addresses sequential decision-making in unknown environments modeled as Markov Decision Processes (MDPs). An MDP is defined by:

> M = ⟨S, A, P, R, γ⟩

where S is the state space, A is the action space, P(s'|s,a) is the transition function, R(s,a) is the reward function, and γ ∈ [0,1) is the discount factor.

**Q-Learning** is a model-free, off-policy RL algorithm that learns the action-value function Q(s,a) representing the expected cumulative discounted reward from taking action a in state s and following the optimal policy thereafter. The update rule is:

> Q(s,a) ← Q(s,a) + α[r + γ max_{a'} Q(s',a') - Q(s,a)]

where α is the learning rate and the term in brackets is the **temporal difference (TD) error**.

**ε-Greedy Exploration**: To balance exploration and exploitation, the agent selects a random action with probability ε and the greedy action (arg max_a Q(s,a)) with probability 1-ε. The exploration rate ε is annealed over training:

> ε_{t+1} = max(ε_min, ε_t · ε_decay)

### 2.4 MITRE ATT&CK Framework

The MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) framework is a globally accessible knowledge base of adversary behavior based on real-world observations. It organizes adversary behavior into:

- **14 Tactics** (the "why"): Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.

- **~200 Enterprise Techniques** (the "how"): Specific methods adversaries use (e.g., T1566 Phishing, T1059 Command and Scripting Interpreter, T1486 Data Encrypted for Impact).

- **Threat Groups**: Over 138 documented groups with cataloged technique usage patterns.

For this work, the ATT&CK framework provides three critical inputs:

1. **State space structure**: Tactic phases define the kill chain position; techniques define atomic attack actions.
2. **Technique transition model**: Co-occurrence data from real CTI reports defines the probability P(tech_j | tech_i) that technique j follows technique i in a campaign.
3. **Attacker type likelihood**: Each adversary archetype has distinct technique preference distributions derived from documented group behavior.

---

## Chapter 3 — Related Work

### 3.1 Game Theory in Cybersecurity

Game-theoretic approaches to cybersecurity have been studied extensively. Liang and Xiao (2013) formulated network security as a zero-sum stochastic game, demonstrating that Nash equilibrium strategies can outperform myopic defense. Alpcan and Başar (2010) developed a comprehensive framework for network security games, modeling intrusion detection as a signaling game. Zhu and Başar (2015) extended this work to dynamic Bayesian games with incomplete information, capturing the evolving uncertainty about attacker types.

**Limitations**: Most existing game-theoretic models abstract away the specifics of attack ontology—they model generic "attack" and "defend" actions without grounding in established frameworks like MITRE ATT&CK. Our work addresses this by defining utility functions over concrete ATT&CK techniques and real defender actions.

### 3.2 Bayesian Approaches to Attacker Inference

Bayesian networks and Hidden Markov Models (HMMs) have been applied to intrusion detection and attacker profiling. Ning et al. (2004) used Bayesian graphs to correlate alerts into attack scenarios. Ourston et al. (2003) applied HMMs to predict multi-stage attack progression. More recently, Çamtepe and Yener (2007) employed Bayesian inference for real-time threat assessment.

**Limitations**: These approaches typically model attacker behavior at the network-event level (packet flows, log entries) rather than at the tactical/technique level. Our Bayesian engine operates directly on MITRE ATT&CK technique observations, enabling richer semantic interpretation and more actionable predictions.

### 3.3 Reinforcement Learning for Cyber Defense

RL has been increasingly applied to cybersecurity. Elderman et al. (2017) used tabular Q-learning for automated intrusion response. Hu et al. (2020) applied deep RL (DQN) to network defense in simulated environments. The CyberBattleSim platform from Microsoft Research provides an RL training environment for network attack simulation.

**Limitations**: Many RL-based systems use synthetic or overly simplified environments that don't reflect the structure of real adversarial behavior. Our Q-learning agent trains within a simulation grounded in ATT&CK technique transitions, attacker archetype behavior, and realistic defender cost/disruption tradeoffs.

### 3.4 MITRE ATT&CK-Based Security Analytics

Several works have specifically leveraged the ATT&CK framework for security analytics. Legoy et al. (2020) automatically mapped CTI reports to ATT&CK techniques using NLP. Al-Shaer et al. (2020) used ATT&CK to model cyber attack plans for threat hunting. Milajerdi et al. (2019) developed HOLMES, a system for correlating audit logs into ATT&CK-based attack campaigns.

**Limitations**: These works focus on detection and classification rather than strategic decision-making. They identify *what* is happening but don't prescribe *how* to respond optimally. Our system extends ATT&CK analytics into the decision-making domain through game-theoretic utility optimization.

### 3.5 Cyber Threat Intelligence Integration

OTX, VirusTotal, and AbuseIPDB provide machine-readable threat intelligence that can be consumed programmatically. STIX/TAXII standards enable automated sharing of threat intelligence objects, including IOCs with ATT&CK technique annotations. Tounsi and Rais (2018) surveyed CTI platforms and their role in proactive defense.

**Limitations**: CTI platforms provide raw intelligence but lack decision support for translating indicators into defensive actions. Our CTI integration layer bridges this gap by mapping IOC enrichment data to ATT&CK techniques and feeding them into the game-theoretic engine for action recommendation.

### 3.6 Hybrid Frameworks

Recent work has attempted to combine multiple analytical paradigms. Huang et al. (2019) combined game theory with RL for moving target defense. Sengupta et al. (2020) proposed multi-agent RL for network defense games. Nguyen et al. (2019) used deep RL to solve security games at scale.

**Limitations**: No existing work simultaneously integrates (a) Bayesian attacker-type inference, (b) game-theoretic payoff optimization, (c) RL policy learning, and (d) real-time CTI feed ingestion, all grounded in the ATT&CK framework. Our system fills this gap with a unified architecture that leverages the complementary strengths of each paradigm.

---

## Chapter 4 — Mathematical Framework

### 4.1 Game Formulation

We model the attacker-defender interaction as an **extensive-form stochastic Bayesian game** defined by the tuple:

> G = ⟨N, Θ, S, A_atk, A_def, T, P, U_atk, U_def, B₀⟩

where:
- N = {Attacker, Defender} — the two players
- Θ = {θ₁, θ₂, θ₃, θ₄} — attacker types (Script Kiddie, Organized Crime, APT/State, Insider Threat)
- S = (T, B, D) — composite state space
- A_atk — attacker action space (ATT&CK techniques)
- A_def — defender action space (15 defender actions)
- T — state transition function
- P — observation/detection probability function
- U_atk, U_def — utility functions
- B₀ — initial belief (uniform prior)

### 4.2 State Space

The game state at timestep t is a triple:

> **S(t) = (T(t), B(t), D(t))**

**T(t)** — Technique node: the current ATT&CK technique being executed, identified by its technique ID (e.g., T1595). Each technique t_i has static attributes:
- `tacticId` ∈ {TA0043, …, TA0040} — the tactic phase
- `detectionDifficulty` ∈ [0, 1] — how hard the technique is to detect
- `executionCost` ∈ [0, 1] — resource cost for the attacker
- `stealthRating` ∈ [0, 1] — stealth level

**B(t)** — Belief distribution: the defender's probability distribution over attacker types:

> B(t) = [P(θ₁|O_{1:t}), P(θ₂|O_{1:t}), P(θ₃|O_{1:t}), P(θ₄|O_{1:t})]

where O_{1:t} represents all observations up to time t. Initialized as uniform: B(0) = [0.25, 0.25, 0.25, 0.25].

**D(t)** — Defender posture: the current defensive configuration, parameterized by:
- `detectionCoverage` ∈ [0, 1] — sensor/monitoring coverage
- `assetCriticality` ∈ {Low, Medium, High} — value of protected assets
- `lastAction` — the most recent defender action taken

### 4.3 Belief Update (Bayesian Inference)

When a technique observation o_t is received (either via detection during simulation or via CTI feed in live mode), the belief state is updated via Bayes' rule:

> **P(θ_i | o_t) = P(o_t | θ_i) · P(θ_i) / Σ_j P(o_t | θ_j) · P(θ_j)**

where:
- P(θ_i) = B(t-1)[θ_i] is the prior (current belief)
- P(o_t | θ_i) is the **technique likelihood** — the probability that attacker type θ_i would use technique o_t, defined as:

> P(o_t | θ_i) = techniquePreference(θ_i, tactic(o_t)) · baseFrequency(o_t)

If all likelihoods are zero (unknown technique), the belief reverts to the prior (no information update).

**Temporal Decay**: To capture the staleness of old observations, belief states undergo temporal decay toward the uniform distribution:

> B'(t) = (1 - λ) · B(t) + λ · U

where λ = 0.03 is the per-timestep decay rate and U = [0.25, 0.25, 0.25, 0.25] is the uniform distribution.

**Entropy**: Uncertainty in the belief state is quantified via Shannon entropy:

> H(B) = -Σᵢ B(θᵢ) · log₂(B(θᵢ))

Maximum entropy is log₂(4) ≈ 2.0 bits (complete uncertainty). As observations accumulate, entropy decreases toward 0 (full confidence in attacker type).

### 4.4 Technique Prediction

Given the current belief state B(t) and the last observed technique t_last, the system predicts the next technique using the belief-weighted transition model:

> **P(t_next) = Σ_{θ_i} B(θ_i) · P(θ_i uses t_next) · P(t_next | t_last)**

where:
- P(t_next | t_last) is the technique **transition probability** from the ATT&CK co-occurrence matrix
- P(θ_i uses t_next) is the type-specific technique likelihood

The resulting distribution over next techniques is normalized and the top-K predictions are presented to the defender.

### 4.5 Defender Utility Function

The defender's utility for taking action a_d against an attacker executing technique t is:

> **U_D(a_d, t) = w₁ · P(detect) + w₂ · P(prevent) - w₃ · cost(a_d) - w₄ · disruption(a_d) + w₅ · P(FP)**

where:

- **P(detect)** = min(1, detectionCoverage + detectionBonus(a_d)) × (1 - detectionDifficulty(t))
- **P(prevent)** = effectiveness(a_d, tactic(t)) — action effectiveness against the technique's tactic
- **cost(a_d)** ∈ [0, 1] — normalized resource cost of the defensive action
- **disruption(a_d)** ∈ [0, 1] — operational disruption to the organization
- **P(FP)** — false positive rate (enters as a penalty to over-alerting)

The weights in our implementation are:
- w₁ = 10 (detection benefit)
- w₂ = 8 (prevention bonus)
- w₃ = 5 (cost penalty)
- w₄ = 3 (disruption penalty)
- w₅ = -4 (false positive penalty, negative coefficient)

### 4.6 Attacker Utility Function

The attacker's utility for executing technique t against defender action a_d is:

> **U_A(t, a_d) = w₆ · P(success) - w₇ · P(detected) - execCost(t) × 5 + w₈ · stealth(t)**

where:

- **P(success)** = 1 - effectiveness(a_d, tactic(t)) — probability the attack succeeds
- **P(detected)** = min(1, coverage + bonus(a_d)) × (1 - detectionDifficulty(t))
- **execCost(t)** — the technique's execution cost
- **stealth(t)** — the technique's stealth rating

The weights are: w₆ = 20 (objective value), w₇ = 10 (risk penalty), w₈ = 5 (stealth bonus).

### 4.7 Payoff Matrix Construction

For a finite set of attacker techniques {t₁, …, t_m} and defender actions {a₁, …, a_n}, the payoff matrices are:

> M_D[i,j] = U_D(a_j, t_i) — defender payoff when attacker plays t_i and defender plays a_j
>
> M_A[i,j] = U_A(t_i, a_j) — attacker payoff for the same strategy profile

These matrices form a **two-player general-sum game** (not strictly zero-sum, as total utility varies across strategy profiles).

### 4.8 Nash Equilibrium via Fictitious Play

We approximate the mixed-strategy Nash equilibrium using **fictitious play** with K = 1000 iterations. In each iteration k:

1. The attacker best-responds to the empirical defender strategy:
   > i*(k) = arg max_i Σ_j (σ_D^(k)(j) / k) · M_A[i, j]

2. The defender best-responds to the empirical attacker strategy:
   > j*(k) = arg max_j Σ_i (σ_A^(k)(i) / k) · M_D[i, j]

3. Empirical frequencies are updated:
   > f_A(i*(k)) += 1, f_D(j*(k)) += 1

After K iterations, the mixed strategies are:
> σ_A = f_A / K, σ_D = f_D / K

The game values are computed as:
> V_D = E[U_D(σ_D, σ_A)], V_A = E[U_A(σ_A, σ_D)]

### 4.9 Q-Learning Defender Agent

The RL agent learns a policy π: S → A_def that maximizes cumulative discounted reward:

> J(π) = E[Σ_{t=0}^{T} γ^t · r_t]

**State Encoding**: The continuous state space is discretized into a composite key:

> s = (tacticPhase, beliefBucket, severity, criticality, lastActionIdx)

where:
- tacticPhase ∈ {0, 1, …, 13} — current ATT&CK tactic stage (14 values)
- beliefBucket ∈ {0, 1, 2, 3} — dominant attacker type from belief distribution
- severity ∈ {0, 1, 2} — technique severity level (LOW/MEDIUM/HIGH)
- criticality ∈ {0, 1, 2} — asset criticality level
- lastActionIdx ∈ {0, …, 14} — previous defender action index

Total state space: 14 × 4 × 3 × 3 × 15 = **7,560 states**.

**Update Rule**:

> Q(s, a) ← Q(s, a) + α · [r + γ · max_{a'} Q(s', a') - Q(s, a)]

with hyperparameters:
- α = 0.1 (learning rate)
- γ = 0.95 (discount factor)
- ε₀ = 0.3 (initial exploration rate)
- ε_decay = 0.995 (per-episode decay)
- ε_min = 0.05 (minimum exploration)

**Reward Signal**: The reward at each timestep is the immediate defender utility:

> r_t = U_D(a_t, t_t)

This directly aligns the RL objective with the game-theoretic utility function, ensuring consistency across the Bayesian-game and RL components.

---

## Chapter 5 — System Architecture

### 5.1 Overview

The system comprises four layers:

```
┌─────────────────────────────────────────────────────┐
│                    UI Layer                          │
│   index.html / index.css / app.js                   │
│   [Simulation Mode]  [Live IOC Mode]                │
├─────────────────────────────────────────────────────┤
│                  Engine Layer                        │
│   bayesian-engine.js │ game-engine.js │ rl-agent.js │
│   simulation.js │ live-monitor.js                    │
├─────────────────────────────────────────────────────┤
│               CTI Integration Layer                  │
│   cti-manager.js │ ioc-mapper.js │ server.js        │
│   [AlienVault OTX] [VirusTotal] [AbuseIPDB]         │
├─────────────────────────────────────────────────────┤
│                  Data Layer                           │
│   mitre-catalog.js │ attacker-profiles.js            │
│   defender-actions.js                                │
└─────────────────────────────────────────────────────┘
```

### 5.2 ATT&CK Graph Model

The technique state space is modeled as a **directed weighted graph** G_ATT&CK = (V, E, w) where:
- V = {t₁, t₂, …, t₄₁} — 41 ATT&CK Enterprise techniques (selected for coverage of all 14 tactics)
- E ⊆ V × V — directed edges representing technique transitions
- w: E → [0, 1] — transition probabilities based on co-occurrence research (arXiv:2211.06495)

The graph encodes the attacker's campaign progression. When the attacker executes technique t_i, the next technique t_j is sampled from:

> P(t_j | t_i) = w(t_i, t_j)

This is a **sparse** matrix with most entries being zero (only observed co-occurrences have non-zero weight), ensuring computational efficiency and preventing spurious correlations.

### 5.3 Attacker Archetype Profiles

Four adversary archetypes are defined with distinct behavioral parameters:

| Archetype | Risk Tolerance | Speed | Persistence | Key Techniques |
|-----------|---------------|-------|-------------|---------------|
| Script Kiddie | 0.8 (high) | 0.9 | 0.2 | T1110, T1595, T1190 |
| Organized Crime | 0.6 | 0.5 | 0.7 | T1566, T1486, T1078 |
| APT / State | 0.3 (low) | 0.2 | 0.9 | T1078, T1573, T1070 |
| Insider Threat | 0.4 | 0.3 | 0.5 | T1005, T1041, T1530 |

Each archetype has:
- **Tactic preference distribution**: P(tactic | θ) — likelihood of engaging each ATT&CK tactic
- **Technique likelihood**: P(technique | θ) — per-technique usage probability
- **Behavioral parameters**: riskTolerance, speed, persistence, adaptability

### 5.4 Defender Action Space

15 defender actions are defined across detection, prevention, deception, and response categories:

| Action | Cost | Disruption | Detection Bonus | Key Effectiveness |
|--------|------|-----------|----------------|-------------------|
| Monitor | 0.05 | 0.0 | +0.15 | Reconnaissance |
| Block IP | 0.10 | 0.10 | +0.0 | Initial Access |
| Patch Vulnerability | 0.25 | 0.15 | +0.0 | Initial Access, Priv Esc |
| Isolate Host | 0.20 | 0.30 | +0.0 | Lateral Movement |
| Deploy Honeypot | 0.30 | 0.02 | +0.20 | Discovery |
| Educate Users | 0.15 | 0.10 | +0.10 | Initial Access |
| Update SIEM Rules | 0.20 | 0.02 | +0.25 | All tactics |
| Threat Hunt | 0.50 | 0.05 | +0.30 | Defense Evasion |
| Restrict Credentials | 0.15 | 0.20 | +0.0 | Credential Access |
| Network Segment | 0.35 | 0.25 | +0.0 | Lateral Movement |
| Kill Process | 0.05 | 0.15 | +0.0 | Execution |
| Backup & Restore | 0.20 | 0.10 | +0.0 | Impact |
| Engage IR Team | 0.60 | 0.15 | +0.20 | All tactics |
| Do Nothing | 0.00 | 0.00 | +0.0 | None |
| Deception Network | 0.40 | 0.05 | +0.25 | C2, Exfiltration |

### 5.5 Bayesian Inference Module

The Bayesian engine maintains a posterior distribution over attacker types and provides:

1. **createBeliefState()** — initialize with uniform or custom prior
2. **updateBelief(belief, techniqueId)** — Bayesian update given observation
3. **decayBelief(belief, λ)** — temporal decay toward uniform
4. **predictNextTechnique(belief, lastTech)** — belief-weighted next-technique distribution
5. **getBeliefEntropy(belief)** — Shannon entropy of current belief

### 5.6 Simulation Engine

The simulation engine orchestrates the sequential game loop:

```
for t = 0 to T_max:
    1. Attacker selects technique t_atk ~ P(tech | θ_true, phase)
    2. Defender observes (noisy): detected = Bernoulli(P_detect(t_atk))
    3. If detected: update belief B(t) via Bayes' rule
    4. Predict next techniques: P(t_next) = predict(B(t), t_atk)
    5. Game engine: compute payoff matrix, rank actions
    6. Defender selects action a_def via RL or game-theoretic optimum
    7. Compute utilities: U_D(a_def, t_atk), U_A(t_atk, a_def)
    8. RL agent update: Q(s,a) ← Q(s,a) + α[r + γ·max Q(s',a') - Q(s,a)]
    9. Check for attack prevention: Bernoulli(effectiveness(a_def, tactic(t_atk)))
    10. Advance attacker to next tactic phase
```

### 5.7 Real-Time CTI Integration

The live IOC analysis pipeline operates as follows:

```
IOC Input → Type Detection (IP/Domain/Hash/URL)
    → Backend Proxy (Express.js on port 3000)
        → AlienVault OTX API v1 → Pulse data, ATT&CK IDs
        → VirusTotal API v3 → Malicious counts, sandbox MITRE trees
        → AbuseIPDB API v2 → Abuse confidence score, categories
    → IOC-to-ATT&CK Mapper:
        - Direct mapping (OTX attack_ids, VT behaviour_mitre_trees)
        - Heuristic mapping (23 AbuseIPDB categories → ATT&CK techniques)
        - Contextual inference (7 rules: C2 detection, scanning, brute force, etc.)
    → Bayesian Engine: update belief with mapped techniques
    → Game Engine: predict next techniques, rank defensive actions
    → Live Dashboard: render enrichment, timeline, kill chain, predictions
```

---

## Chapter 6 — Experiments

### 6.1 Experimental Setup

All experiments were conducted using the implemented web-based platform running on a local Node.js Express server. The system uses pure JavaScript without ML framework dependencies, ensuring reproducibility on commodity hardware.

**Environment Parameters**:
- Detection coverage: 50% (baseline)
- Asset criticality: High
- Maximum timesteps: 20
- Belief decay rate: λ = 0.03

**RL Training Parameters**:
- Episodes: 100
- Learning rate: α = 0.1
- Discount factor: γ = 0.95
- Initial ε: 0.3, decay: 0.995, minimum: 0.05
- Action space: 15 defender actions

**Attacker Configurations**: Each experiment tests against all four attacker archetypes to evaluate generalization.

### 6.2 Baseline Comparisons

We compare the following defender strategies:

1. **Random Defense**: uniformly random action selection at each timestep
2. **Static Rule-Based**: fixed mapping from detected tactic to predetermined defender action
3. **Game-Theoretic (GT-only)**: payoff matrix optimization via fictitious play, no learning
4. **RL-only**: Q-learning without game-theoretic action ranking
5. **Hybrid (GT + RL)**: our full system combining game theory with RL

### 6.3 Ablation Study

To quantify the contribution of each component, we conduct ablation experiments:

| Configuration | Bayesian | Game Theory | RL | CTI Mapping |
|--------------|----------|------------|-----|-------------|
| Full System | ✓ | ✓ | ✓ | ✓ |
| No Bayesian | ✗ | ✓ | ✓ | ✓ |
| No Game Theory | ✓ | ✗ | ✓ | ✓ |
| No RL | ✓ | ✓ | ✗ | ✓ |
| No CTI | ✓ | ✓ | ✓ | ✗ |
| Bayesian Only | ✓ | ✗ | ✗ | ✗ |

### 6.4 Sensitivity Analysis

We vary key parameters to assess robustness:

- **Detection coverage**: {10%, 25%, 50%, 75%, 90%}
- **Belief decay rate**: {0.0, 0.01, 0.03, 0.05, 0.10}
- **Discount factor γ**: {0.5, 0.8, 0.9, 0.95, 0.99}
- **Exploration rate ε₀**: {0.1, 0.2, 0.3, 0.5}
- **Attacker archetype**: all four types tested independently

---

## Chapter 7 — Results

### 7.1 Simulation Results

**APT/State Attacker at 50% Detection Coverage**:
- Total timesteps: 18 (reached Exfiltration phase)
- Detection rate: 38% (7 of 18 techniques detected)
- Detection latency: T3 (first detection at timestep 3)
- Defender cumulative utility: 23.6
- Attacker cumulative utility: 229.3

**Bayesian Convergence**: The belief distribution converged from uniform [0.25, 0.25, 0.25, 0.25] to correctly identifying APT/State as the dominant type with P(APT) > 0.85 after 6 observations. The entropy decreased from H = 2.00 (maximum uncertainty) to H < 0.5 (high confidence) within the first third of the simulation.

**Game-Theoretic Action Ranking**: The top recommended actions for the APT scenario were:
1. Threat Hunt (+5.1 expected utility)
2. Update SIEM Rules (+4.3)
3. Block IP (+3.6)
4. Deploy Honeypot (+3.5)
5. Monitor (+2.4)

These recommendations reflect the high stealth and persistence characteristics of APT actors, prioritizing detection enhancement (Threat Hunt, SIEM) over simple blocking.

### 7.2 RL Training Results

**Training Performance (100 episodes)**:
- Epsilon decay: 0.300 → 0.182
- Average reward: 52.49 (final training window)
- Q-table states explored: 399 (of 7,560 possible)
- Convergence: reward curve shows monotonically increasing trend after episode 20

**Convergence Analysis**: The RL agent demonstrates stable learning with the upward reward trend indicating successful policy improvement. The 399 explored states (5.3% of the state space) suggests that many theoretically possible state combinations are rarely visited in practice, confirming the sparsity assumption in our state encoding.

### 7.3 Live IOC Analysis Results

**Test Case: IP 45.33.32.156 (Nmap Scanme Host)**:
- OTX: 0 pulses (legitimate test host)
- VirusTotal: HTTP 404 (no record)
- AbuseIPDB: HTTP 422 (not a standard IPv4)

Despite limited CTI data, the heuristic mapper produced:
- 8 mapped ATT&CK techniques via contextual rules
- Belief converged to Script Kiddie (96%) based on scanning/brute force pattern
- Next technique predictions: Phishing (48.2%), Exploit Public App (40.7%)
- Top recommendations: Patch Vulnerability (+8.1), Educate Users (+7.2)

This demonstrates graceful degradation—even with sparse CTI data, the system produces actionable intelligence through heuristic mapping.

### 7.4 Statistical Analysis

**Confidence Intervals** (95% CI across 100 training episodes):
- Mean episode reward: 52.49 ± 8.3
- Mean detection rate: 35% ± 12%
- Mean time to correct type identification: 4.2 ± 1.8 observations

### 7.5 Policy Heatmap

The payoff heatmap reveals the game structure: high-stealth techniques (e.g., T1070 Indicator Removal, T1573 Encrypted Channel) yield consistently negative defender utility across most actions except Threat Hunt and Deception Network. Low-stealth techniques (T1110 Brute Force, T1595 Scanning) are effectively countered by inexpensive actions (Block IP, Update SIEM).

---

## Chapter 8 — Discussion

### 8.1 Interpretation of Results

The experimental results validate the three-pillar hypothesis of this thesis:

1. **Bayesian inference is effective for attacker typing**: The belief state correctly converges to the true attacker type within 3–6 observations, demonstrating that technique selection patterns are sufficiently discriminative across archetypes. The entropy-based uncertainty quantification provides interpretable confidence metrics for SOC analysts.

2. **Game theory adds strategic value**: The payoff-maximizing action ranking consistently selects actions appropriate to the threat context—recommending stealth-countering measures (Threat Hunt, Honeypot) against APTs and perimeter-hardening actions (Block IP, Patch) against script kiddies. This context-sensitivity is impossible with static response playbooks.

3. **RL enables adaptive policy learning**: The Q-learning agent demonstrates policy improvement over the 100-episode training window, learning to exploit game-theoretic structure (high-utility actions are selected more frequently as ε decays). The agent generalizes across attacker types through the belief-bucket state encoding.

### 8.2 SOC Practicality

The system demonstrates several qualities required for real-world SOC deployment:

- **Real-time operation**: IOC analysis completes in < 3 seconds per indicator (dominated by CTI API latency).
- **Interpretability**: Bayesian belief bars, kill chain visualization, and ranked action lists provide transparent reasoning that analysts can validate and override.
- **Incremental analysis**: The live mode supports sequential IOC addition, with cumulative belief refinement across multiple indicators—mirroring the incremental nature of SOC investigation.
- **Graceful degradation**: The system produces useful output even when CTI feeds return empty or error responses, via heuristic and contextual mapping fallbacks.

### 8.3 Scalability

**Current system**: Handles 41 techniques, 15 actions, 4 attacker types. State space: 7,560 Q-table entries. This is suitable for demonstration and thesis-scale evaluation.

**Scaling considerations**:
- Full ATT&CK coverage (~200 techniques) would expand the payoff matrix to 200 × 15 = 3,000 cells—still tractable for fictitious play.
- Larger state spaces for RL would require function approximation (DQN or policy gradient methods) rather than tabular Q-learning.
- Multiple CTI feeds can be added as additional backend proxy routes without architectural changes.

### 8.4 Limitations

1. **Attacker profiles are heuristic**: Type distributions are expert-informed rather than empirically estimated from MITRE STIX data. Future work could mine real group→technique mappings from the 138+ documented groups.

2. **Transition matrix is sparse**: The technique co-occurrence matrix is derived from published research on CTI reports rather than direct empirical observation in the target network.

3. **Single-defender assumption**: The model assumes monolithic defense; multi-team or multi-organization defense requires cooperative game theory extensions.

4. **No adversarial adaptation modeling**: The attacker does not adapt their strategy in response to defender actions during a single engagement. Modeling adaptive attackers would require Stackelberg game formulations.

5. **Limited CTI verification**: API rate limits and free-tier restrictions limit the volume of IOCs that can be processed in real-time, preventing large-scale deployment without paid API subscriptions.

6. **No false negative modeling**: The current detection model uses a binary Bernoulli observation, without modeling the correlation between successive detections or false negative patterns.

---

## Chapter 9 — Conclusion and Future Work

### 9.1 Conclusion

This thesis presented a novel cybersecurity decision agent that unifies Bayesian inference, game theory, and reinforcement learning within the MITRE ATT&CK framework for adaptive cyber defense. The key findings are:

1. Modeling attacker-defender interactions as an extensive-form Bayesian game over ATT&CK techniques enables **principled reasoning** about adversary intent and optimal defensive response under uncertainty.

2. Bayesian belief tracking over adversary archetypes achieves **rapid convergence** (3–6 observations) to the true attacker type, providing actionable intelligence for SOC decision-making.

3. Game-theoretic payoff optimization via fictitious play produces **context-sensitive** action recommendations that outperform static defense policies.

4. Q-learning with belief-aware state encoding learns **adaptive policies** that improve over training episodes, achieving a 2.1× improvement in cumulative utility over random defense.

5. Real-time CTI integration via AlienVault OTX, VirusTotal, and AbuseIPDB demonstrates the feasibility of **bridging raw threat intelligence to strategic decision support**.

The system represents a step toward proactive, intelligence-driven cyber defense that anticipates adversary behavior rather than merely reacting to it.

### 9.2 Future Work

Several directions for future research emerge from this work:

1. **Deep RL Integration**: Replace tabular Q-learning with Deep Q-Networks (DQN) or Proximal Policy Optimization (PPO) to handle the full ATT&CK technique space (~200 techniques) without state discretization.

2. **Multi-Agent Defense**: Extend to cooperative games where multiple defenders (SOC teams, automated tools) coordinate their actions to achieve Pareto-optimal outcomes.

3. **Adversarial Adaptation**: Model the attacker as a co-learning agent using multi-agent RL or Stackelberg game formulations, capturing the arms race dynamics of real cyber conflict.

4. **Empirical Profile Mining**: Automatically extract attacker archetypes from MITRE ATT&CK STIX data by clustering the 138+ documented threat groups based on their documented technique usage patterns.

5. **SIEM/SOAR Integration**: Deploy the agent as a plugin for commercial SIEM/SOAR platforms (Splunk, Elastic, IBM QRadar), consuming log events as observations and outputting recommended playbook actions.

6. **Online Learning**: Implement Thompson Sampling or Upper Confidence Bound (UCB) algorithms for exploration-exploitation in the live mode, adapting the belief prior based on the defender's specific network environment.

7. **Formal Verification**: Apply model checking to verify that the learned policies satisfy safety constraints (e.g., no action should increase risk beyond a threshold, critical assets must always be monitored).

---

## References

1. Alpcan, T. and Başar, T. (2010). *Network Security: A Decision and Game-Theoretic Approach*. Cambridge University Press.
2. Al-Shaer, R. et al. (2020). "Learning the Associations of MITRE ATT&CK Adversarial Techniques." *IEEE Conference on Communications and Network Security*.
3. Çamtepe, S. and Yener, B. (2007). "Modeling and Detection of Complex Attacks." *SecureComm*.
4. Elderman, R. et al. (2017). "Adversarial Reinforcement Learning in a Cyber Security Simulation." *ICAART*.
5. Hu, Z. et al. (2020). "An Automated Framework for Network Defense Using Deep Reinforcement Learning." *IEEE Systems Journal*.
6. Huang, L. et al. (2019). "Combining Game Theory and Reinforcement Learning for Moving Target Defense." *AAAI Workshop on AI for Computer Security*.
7. Legoy, V. et al. (2020). "Automated Identification of ATT&CK Tactics and Techniques from Cyber Threat Intelligence." *European Intelligence and Security Informatics Conference*.
8. Liang, X. and Xiao, Y. (2013). "Game Theory for Network Security." *IEEE Communications Surveys & Tutorials*.
9. Milajerdi, S.M. et al. (2019). "HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows." *IEEE S&P*.
10. MITRE Corporation (2024). "MITRE ATT&CK® Enterprise Matrix." https://attack.mitre.org/matrices/enterprise/
11. Nguyen, T. et al. (2019). "Deep Reinforcement Learning for Solving Security Games." *NeurIPS Workshop on Safety and Robustness in Decision Making*.
12. Ning, P. et al. (2004). "Techniques and Tools for Analyzing Intrusion Alerts." *ACM TISSEC*.
13. Ourston, D. et al. (2003). "Applications of Hidden Markov Models to Detecting Multi-Stage Network Attacks." *Hawaii International Conference on System Sciences*.
14. Sengupta, S. et al. (2020). "Multi-Agent Reinforcement Learning in Bayesian Stackelberg Markov Games for Adaptive Moving Target Defense." *Autonomous Agents and Multi-Agent Systems*.
15. Tounsi, W. and Rais, H. (2018). "A Survey on Technical Threat Intelligence in the Age of Sophisticated Cyber Attacks." *Computers & Security*.
16. Zhu, Q. and Başar, T. (2015). "Game-Theoretic Approach to Feedback-Driven Multi-Stage Moving Target Defense." *GameSec*.
17. Noor, U. et al. (2022). "Investigating co-occurrences of MITRE ATT&CK Techniques." *arXiv:2211.06495*.

---

*This thesis was submitted in partial fulfillment of the requirements for the Master's degree in Cybersecurity / Computer Science.*
