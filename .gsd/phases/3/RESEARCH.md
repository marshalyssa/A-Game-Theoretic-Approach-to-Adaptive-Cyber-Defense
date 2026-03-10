# Phase 3 Research: Experiment Automation

## Overview
Phase 3 builds an automated experiment pipeline to systematically evaluate the system across all
configurations in Chapter 6–7. This is pure internal work — all code builds on the existing
simulation engine (`simulation.js`, `rl-agent.js`). No new external dependencies.

## Decision: Discovery Level 0
All deliverables use:
- Existing `runEpisode()` and `runTraining()` from `js/engine/simulation.js`
- Existing `ATTACKER_TYPES` from `js/data/attacker-profiles.js`
- Node.js built-in `fs`, `path` for CSV/JSON export
- Canvas 2D API (already used in `app.js`) behind a tiny offscreen helper for chart images

## Experiment Design
The planned experiment matrix: **4 attacker types × 5 detection levels × 50 episodes each = 1,000 total runs**

| Attacker Type    | Detection Levels |
|------------------|-----------------|
| script_kiddie    | 0%, 25%, 50%, 75%, 100% |
| organized_crime  | 0%, 25%, 50%, 75%, 100% |
| apt_state        | 0%, 25%, 50%, 75%, 100% |
| insider_threat   | 0%, 25%, 50%, 75%, 100% |

**Metrics per episode**: Detection Rate, Prevention Rate, Cumulative Defender Utility, Attacker Utility, Steps, Time-to-Detection.

## Statistical Methods
- **95% confidence intervals**: mean ± 1.96 × (std / √n)
- **p-values**: paired t-test between attacker types at matching detection levels using Node.js calculation
- **Effect size**: Cohen's d between best and worst performing defender configurations

## Output Files
- `experiments/results.json` — Full structured output by attacker type + detection level
- `experiments/results.csv` — Flat table suitable for thesis tables
- `experiments/charts/*.png` — Convergence plots per attacker type, ablation bar chart (detection level vs utility)

## Implementation Notes
- The runner must be a **CLI script** (`scripts/run-experiments.mjs`) so it works from the terminal without a browser.
- ESM imports needed for `simulation.js` and data modules.
- Chart generation: use `canvas` npm package for server-side PNG rendering (already available via npm — will verify).
- Ensure atomic progress logging so user can see progress during long run.
