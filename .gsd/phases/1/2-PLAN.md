---
phase: 1
plan: 2
wave: 1
---

# Plan 1.2: RL Agent + Simulation Integration Tests

## Objective
Write unit tests for the RL agent (Q-learning correctness) and integration tests for the simulation pipeline (full game loop produces valid output). These tests verify the learning dynamics and end-to-end orchestration.

## Context
- .gsd/SPEC.md
- .gsd/ARCHITECTURE.md
- js/engine/rl-agent.js
- js/engine/simulation.js
- js/engine/bayesian-engine.js
- js/engine/game-engine.js
- js/data/mitre-catalog.js
- js/data/attacker-profiles.js
- js/data/defender-actions.js

## Tasks

<task type="auto">
  <name>Unit test rl-agent.js</name>
  <files>tests/rl-agent.test.mjs (NEW)</files>
  <action>
    Test the following properties:
    1. `createAgent()` — returns agent with correct defaults (alpha=0.1, gamma=0.95, epsilon=0.3)
    2. `createAgent(config)` — custom config overrides defaults
    3. `selectAction()` — returns valid actionIdx within [0, numActions)
    4. `selectAction()` — with epsilon=1.0, always explores (all actions should appear over many calls)
    5. `selectAction()` — with epsilon=0.0, always exploits (deterministic for same state)
    6. `updateAgent()` — Q-value changes after update (non-zero TD error)
    7. `updateAgent()` — Q(s,a) moves toward reward when done=true (terminal state)
    8. `decayEpsilon()` — epsilon decreases but stays above epsilon_min
    9. `getAgentStats()` — returns episodes, currentEpsilon, qTableStates, avgReward fields
    10. `resetAgent()` — clears Q-table but preserves config
  </action>
  <verify>npm test — all rl-agent tests pass</verify>
  <done>≥10 test cases pass for rl-agent with zero failures</done>
</task>

<task type="auto">
  <name>Integration test simulation.js</name>
  <files>tests/simulation.test.mjs (NEW)</files>
  <action>
    Test the simulation pipeline end-to-end:
    1. `initSimulation()` — returns valid state with belief, config, gameOver=false
    2. `initSimulation()` — belief starts uniform
    3. `stepSimulation()` — returns a step result with required fields (timestep, technique, detected, belief, etc.)
    4. `stepSimulation()` — advances timestep by 1 each call
    5. `stepSimulation()` — step result contains valid attacker and defender utility numbers
    6. Full episode — `runEpisode()` completes without error and returns final state with gameOver=true
    7. Full episode — final state has metrics object with detectionRate, preventionRate, etc.
    8. Full episode — cumulative utilities are numeric and finite
    9. Training — `runTraining()` over 5 episodes completes without error (smoke test)
    10. Config validation — all 4 attacker types produce valid simulations
  </action>
  <verify>npm test — all simulation tests pass</verify>
  <done>≥10 test cases pass for simulation with zero failures</done>
</task>

## Success Criteria
- [ ] ≥10 rl-agent tests pass
- [ ] ≥10 simulation integration tests pass
- [ ] All 4 attacker types simulated without error
- [ ] Zero test failures
