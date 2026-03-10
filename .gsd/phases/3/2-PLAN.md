---
phase: 3
plan: 2
wave: 1
---

# Plan 3.2: Statistical Analysis Module

## Objective
Implement a statistical analysis module (`scripts/stats.mjs`) that computes confidence intervals, performs paired t-tests between attacker types, and calculates Cohen's d effect sizes. Integrate it into the experiment runner so the JSON output includes a complete `statistics` section.

## Context
- .gsd/SPEC.md
- .gsd/phases/3/RESEARCH.md
- scripts/run-experiments.mjs
- experiments/results.json

## Tasks

<task type="auto">
  <name>Implement statistical computation utilities</name>
  <files>scripts/stats.mjs</files>
  <action>
    Create `scripts/stats.mjs` with the following exported functions (no external dependencies, pure JS):

    - `mean(arr)` — arithmetic mean
    - `std(arr)` — sample standard deviation
    - `ci95(arr)` — { lower, upper, mean, margin } using 1.96 × (std / √n)
    - `pairedTTest(a, b)` — paired t-test returning { t, df, p } (approximated via two-tailed t-distribution lookup table for df 1–1000)
    - `cohensD(a, b)` — effect size: (mean_a - mean_b) / pooledStd

    Each function must guard against empty arrays (return null or throw informative error).
  </action>
  <verify>node -e "import('./scripts/stats.mjs').then(m => { console.log(m.mean([1,2,3])); console.log(m.ci95([1,2,3,4,5])); })"</verify>
  <done>Both values log without errors (mean = 2, ci95 has lower/upper keys).</done>
</task>

<task type="auto">
  <name>Integrate statistics into experiment output</name>
  <files>scripts/run-experiments.mjs</files>
  <action>
    - Import `ci95`, `pairedTTest`, `cohensD` from `./stats.mjs`.
    - After all episodes for a config are complete, call `ci95` on the `defenderUtility` array and attach to `summary.ci95`.
    - After ALL 20 configs complete, add a top-level `crossConfigStats` array to the JSON output that pairs each attacker type against `script_kiddie` as the baseline, computing `pairedTTest` and `cohensD` on cumulative defender utility values.
    - Update `experiments/results.json` to include these stats.
    - Print a short statistics table to stdout: attacker type, mean utility, CI95 interval, p-value vs baseline.
  </action>
  <verify>node scripts/run-experiments.mjs 2>&1 | grep -i "p="</verify>
  <done>Console output includes p-values for each cross-config comparison.</done>
</task>

## Success Criteria
- [ ] `scripts/stats.mjs` exports all 5 statistical functions.
- [ ] `experiments/results.json` summary blocks include `ci95.lower`, `ci95.upper`.
- [ ] Top-level `crossConfigStats` in JSON includes `pairedTTest` and `cohensD` values.
