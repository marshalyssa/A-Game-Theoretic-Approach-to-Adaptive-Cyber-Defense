---
phase: 3
plan: 1
wave: 1
---

# Plan 3.1: Batch Experiment Runner

## Objective
Create a CLI script (`scripts/run-experiments.mjs`) that runs all 20 configurations (4 attacker types × 5 detection levels) for 50 episodes each, collects per-episode metrics, and exports results to `experiments/results.json` and `experiments/results.csv`.

## Context
- .gsd/SPEC.md
- .gsd/ARCHITECTURE.md
- .gsd/phases/3/RESEARCH.md
- js/engine/simulation.js
- js/data/attacker-profiles.js
- js/data/defender-actions.js

## Tasks

<task type="auto">
  <name>Create experiments/ directory and results scaffolding</name>
  <files>
    experiments/.gitkeep
    scripts/run-experiments.mjs
  </files>
  <action>
    - Create `experiments/` directory with a `.gitkeep` placeholder file.
    - Create `scripts/run-experiments.mjs` as a Node.js ESM script with a shebang `#!/usr/bin/env node`.
    - Import `runEpisode`, `createSimConfig` from `./js/engine/simulation.js`.
    - Import `ATTACKER_TYPES` from `./js/data/attacker-profiles.js`.
    - Define `DETECTION_LEVELS = [0, 0.25, 0.50, 0.75, 1.0]` and `EPISODES_PER_CONFIG = 50`.
    - Loop over every `attackerType × detectionLevel` combination (20 total).
    - For each config, run `EPISODES_PER_CONFIG` simulations using `runEpisode()` and collect: `detectionRate`, `preventionRate`, `cumulativeDefenderUtility`, `cumulativeAttackerUtility`, `steps`, `timeToDetection`.
    - Log progress to stdout: `[3/20] apt_state @ 50% — 50 episodes complete`.
  </action>
  <verify>node scripts/run-experiments.mjs --dry-run 2>&1 | head -5</verify>
  <done>Script runs without import errors and logs at least one progress line.</done>
</task>

<task type="auto">
  <name>Export results to JSON and CSV</name>
  <files>
    scripts/run-experiments.mjs
  </files>
  <action>
    - After all 20 configs complete, build a structured `results` object:
      ```json
      {
        "metadata": { "date": "...", "episodesPerConfig": 50 },
        "configs": [
          {
            "attackerType": "apt_state",
            "detectionLevel": 0.5,
            "episodes": [...],
            "summary": { "meanDefenderUtility": ..., "stdDefenderUtility": ..., "meanDetectionRate": ..., "ci95": ... }
          }
        ]
      }
      ```
    - Write `experiments/results.json` using `fs.writeFileSync`.
    - Write `experiments/results.csv` with headers: `attackerType,detectionLevel,episodeNum,detectionRate,preventionRate,defenderUtility,attackerUtility,steps,timeToDetection`.
    - Print a summary table to stdout after completion.
  </action>
  <verify>node scripts/run-experiments.mjs && test -f experiments/results.json && test -f experiments/results.csv</verify>
  <done>Both files exist with correct headers and at least 1000 data rows in the CSV.</done>
</task>

## Success Criteria
- [ ] `scripts/run-experiments.mjs` runs end-to-end without errors.
- [ ] `experiments/results.json` exists with metadata + 20 config blocks.
- [ ] `experiments/results.csv` exists with 1000+ data rows (50 eps × 20 configs).
