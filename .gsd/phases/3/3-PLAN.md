---
phase: 3
plan: 3
wave: 2
---

# Plan 3.3: Chart Generation

## Objective
Generate publication-quality PNG charts from experiment results using the `canvas` npm package:
- **Convergence plots**: defender utility over episodes per attacker type (4 charts)
- **Ablation bar chart**: mean defender utility vs detection level, grouped by attacker (1 chart)

All charts saved to `experiments/charts/`.

## Context
- .gsd/SPEC.md
- .gsd/phases/3/RESEARCH.md
- scripts/run-experiments.mjs
- experiments/results.json

## Tasks

<task type="auto">
  <name>Install canvas and create chart generator</name>
  <files>
    scripts/charts.mjs
    package.json
  </files>
  <action>
    - Install the `canvas` package: `npm install canvas`.
    - Create `scripts/charts.mjs` with:
      - `generateConvergencePlot(configData, outputPath)` — line plot of episode-by-episode defender utility, 800×450px, dark background (`#0a0e17`), cyan line (`#38bdf8`), with axis labels and title.
      - `generateAblationChart(allConfigs, outputPath)` — grouped bar chart of mean defender utility per detection level, grouped by attacker type, 900×500px, using the project's accent colors.
    - Use `createCanvas()` from the `canvas` package (server-side Canvas API).
    - Ensure `experiments/charts/` directory is created if it doesn't exist.
  </action>
  <verify>npm list canvas</verify>
  <done>canvas package resolves in npm tree.</done>
</task>

<task type="auto">
  <name>Integrate chart generation into experiment CLI</name>
  <files>scripts/run-experiments.mjs</files>
  <action>
    - Import `generateConvergencePlot`, `generateAblationChart` from `./charts.mjs`.
    - After exporting JSON/CSV, call:
      - `generateConvergencePlot(config, path)` for each of the 4 attacker types at detection level 50%.
      - `generateAblationChart(allConfigs, 'experiments/charts/ablation.png')` once.
    - Log confirmation lines: `Chart saved: experiments/charts/convergence_apt_state.png`.
  </action>
  <verify>node scripts/run-experiments.mjs 2>&1 | grep "Chart saved"</verify>
  <done>At least 5 chart files exist in experiments/charts/ after script completes.</done>
</task>

## Success Criteria
- [ ] `canvas` package installed.
- [ ] `experiments/charts/` contains 4 convergence PNGs + 1 ablation PNG.
- [ ] Charts use the project's dark theme color palette.
