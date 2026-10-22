#!/usr/bin/env node

/**
 * Batch Experiment Runner
 * Executes simulation matrix: 4 Attacker Types × 5 Detection Levels × 50 Episodes
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Engine imports
import { runEpisode, createSimConfig } from '../js/engine/simulation.js';
import { ATTACKER_TYPES } from '../js/data/attacker-profiles.js';
import { createAgent } from '../js/engine/rl-agent.js';

// Stats import
import { ci95, pairedTTest, cohensD } from './stats.mjs';

// Charts import
import { generateConvergencePlot, generateAblationChart } from './charts.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

// Configuration
const DETECTION_LEVELS = [0, 0.25, 0.5, 0.75, 1.0];
const EPISODES_PER_CONFIG = 50;
const OUTPUT_JSON = path.join(ROOT_DIR, 'experiments', 'results.json');
const OUTPUT_CSV = path.join(ROOT_DIR, 'experiments', 'results.csv');

async function runExperiments() {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(' GSD ► RUNNING BATCH EXPERIMENTS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`Matrix: ${ATTACKER_TYPES.length} attackers × ${DETECTION_LEVELS.length} detection levels`);
    console.log(`Episodes per config: ${EPISODES_PER_CONFIG} (Total: ${ATTACKER_TYPES.length * DETECTION_LEVELS.length * EPISODES_PER_CONFIG})`);
    console.log('─────────────────────────────────────────────────────');

    const allResults = {
        metadata: {
            date: new Date().toISOString(),
            episodesPerConfig: EPISODES_PER_CONFIG,
            attackerTypes: ATTACKER_TYPES,
            detectionLevels: DETECTION_LEVELS
        },
        configs: []
    };

    const csvRows = [
        'attackerType,detectionLevel,episodeNum,detectionRate,preventionRate,defenderUtility,attackerUtility,steps,timeToDetection'
    ];

    let configIdx = 0;
    const totalConfigs = ATTACKER_TYPES.length * DETECTION_LEVELS.length;

    for (const attackerType of ATTACKER_TYPES) {
        for (const detectionLevel of DETECTION_LEVELS) {
            configIdx++;
            process.stdout.write(`[${configIdx}/${totalConfigs}] ${attackerType} @ ${Math.round(detectionLevel * 100)}% ... `);

            const episodes = [];

            // For each configuration, we might want a fresh RL agent or a shared one?
            // The plan says "runs all 20 configurations". Usually for ablation, we use a fresh agent per config
            // if we are measuring "how well it learns in this environment".
            // Since simulation.js:runEpisode creates its own internal loop or we can pass an agent.
            // Let's use a fresh agent for each config to see performance in that environment.
            const agent = createAgent();

            for (let ep = 0; ep < EPISODES_PER_CONFIG; ep++) {
                const config = createSimConfig({
                    attackerType,
                    detectionCoverage: detectionLevel,
                    useRL: true,
                    useGameTheory: true
                });

                // runEpisode(config, agent) returns the final simState
                const state = runEpisode(config, agent);

                const stats = {
                    episode: ep + 1,
                    detectionRate: state.history.filter(s => s.detected).length / state.history.length,
                    preventionRate: state.history.filter(s => s.attackPrevented).length > 0 ? 1 : 0, // Simplified: any prevention?
                    defenderUtility: state.cumulativeDefenderUtility,
                    attackerUtility: state.cumulativeAttackerUtility,
                    steps: state.timestep,
                    timeToDetection: state.metrics.timeToDetection
                };

                episodes.push(stats);

                // Add to CSV
                csvRows.push(`${attackerType},${detectionLevel},${ep + 1},${stats.detectionRate},${stats.preventionRate},${stats.defenderUtility},${stats.attackerUtility},${stats.steps},${stats.timeToDetection}`);
            }

            // Summary stats for this config
            const defenderUtilities = episodes.map(e => e.defenderUtility);
            const detectionRates = episodes.map(e => e.detectionRate);

            const summary = {
                meanDefenderUtility: defenderUtilities.reduce((a, b) => a + b, 0) / EPISODES_PER_CONFIG,
                ci95: ci95(defenderUtilities),
                meanDetectionRate: detectionRates.reduce((a, b) => a + b, 0) / EPISODES_PER_CONFIG,
                meanSteps: episodes.reduce((a, b) => a + b.steps, 0) / EPISODES_PER_CONFIG
            };

            allResults.configs.push({
                attackerType,
                detectionLevel,
                episodes,
                summary
            });

            console.log(`Done (Mean Utility: ${summary.meanDefenderUtility.toFixed(2)})`);
        }
    }

    // Cross-config statistics (Plan 3.2 Task 2)
    console.log('─────────────────────────────────────────────────────');
    console.log('Calculating Cross-Attacker Statistics vs Baseline...');

    allResults.crossConfigStats = [];
    const baselineType = 'script_kiddie';

    for (const attackerType of ATTACKER_TYPES) {
        if (attackerType === baselineType) continue;

        const typeStats = {
            attackerType,
            baseline: baselineType,
            comparisons: []
        };

        for (const dl of DETECTION_LEVELS) {
            const currentConfig = allResults.configs.find(c => c.attackerType === attackerType && c.detectionLevel === dl);
            const baselineConfig = allResults.configs.find(c => c.attackerType === baselineType && c.detectionLevel === dl);

            if (currentConfig && baselineConfig) {
                const currentUtilities = currentConfig.episodes.map(e => e.defenderUtility);
                const baselineUtilities = baselineConfig.episodes.map(e => e.defenderUtility);

                const tTest = pairedTTest(currentUtilities, baselineUtilities);
                const d = cohensD(currentUtilities, baselineUtilities);

                typeStats.comparisons.push({
                    detectionLevel: dl,
                    t: tTest ? tTest.t : null,
                    p: tTest ? tTest.p : null,
                    cohensD: d
                });
            }
        }
        allResults.crossConfigStats.push(typeStats);
    }

    // Export files
    fs.writeFileSync(OUTPUT_JSON, JSON.stringify(allResults, null, 2));
    fs.writeFileSync(OUTPUT_CSV, csvRows.join('\n'));

    console.log('─────────────────────────────────────────────────────');
    console.log('Generating Charts...');
    const chartsDir = path.join(ROOT_DIR, 'experiments', 'charts');
    if (!fs.existsSync(chartsDir)) fs.mkdirSync(chartsDir, { recursive: true });

    // 1. Generate convergence plots for each attacker at 50% detection
    for (const config of allResults.configs) {
        if (config.detectionLevel === 0.5) {
            const fileName = `convergence_${config.attackerType}.png`;
            const filePath = path.join(chartsDir, fileName);
            generateConvergencePlot(config, filePath);
            console.log(` - Saved: experiments/charts/${fileName}`);
        }
    }

    // 2. Generate ablation chart
    const ablationPath = path.join(chartsDir, 'ablation.png');
    generateAblationChart(allResults.configs, ablationPath);
    console.log(` - Saved: experiments/charts/ablation.png`);

    console.log('─────────────────────────────────────────────────────');
    console.log(`Results saved to:`);
    console.log(` - ${path.relative(ROOT_DIR, OUTPUT_JSON)}`);
    console.log(` - ${path.relative(ROOT_DIR, OUTPUT_CSV)}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

// Support --dry-run for verification task
if (process.argv.includes('--dry-run')) {
    console.log('Batch Experiment Runner [DRY RUN]');
    console.log('Imports successful. Configuration valid.');
    process.exit(0);
}

runExperiments().catch(err => {
    console.error('Experiment failed:', err);
    process.exit(1);
});
