/**
 * Integration Tests — Simulation Engine
 * 
 * Tests the full game loop end-to-end, validating interactions
 * between simulation, game-engine, bayesian-engine, and rl-agent.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    createSimConfig,
    initSimulation,
    stepSimulation,
    runEpisode,
    runTraining
} from '../js/engine/simulation.js';
import { createAgent } from '../js/engine/rl-agent.js';
import { ATTACKER_TYPES } from '../js/data/attacker-profiles.js';

// ─── initSimulation ────────────────────────────────────────────────────────

describe('initSimulation', () => {
    it('returns valid state with belief, config, gameOver=false', () => {
        const config = createSimConfig();
        const state = initSimulation(config);

        assert.ok(state.config);
        assert.ok(state.belief);
        assert.equal(state.gameOver, false);
        assert.equal(state.timestep, 0);
        assert.equal(state.cumulativeDefenderUtility, 0);
        assert.equal(state.cumulativeAttackerUtility, 0);
    });

    it('belief starts uniform', () => {
        const config = createSimConfig();
        const state = initSimulation(config);

        const uniform = 1 / ATTACKER_TYPES.length;
        for (const type of ATTACKER_TYPES) {
            assert.ok(Math.abs(state.belief[type] - uniform) < 0.001);
        }
    });
});

// ─── stepSimulation ────────────────────────────────────────────────────────

describe('stepSimulation', () => {
    it('returns a step result with required fields', () => {
        const config = createSimConfig();
        const state = initSimulation(config);
        const rlAgent = createAgent();

        const result = stepSimulation(state, rlAgent);

        assert.ok('timestep' in result, 'missing timestep');
        assert.ok('technique' in result, 'missing technique');
        assert.ok('detected' in result, 'missing detected flag');
        assert.ok('belief' in result, 'missing belief distribution');
        assert.ok('defenderAction' in result, 'missing defenderAction');
        assert.ok('defenderUtility' in result, 'missing defenderUtility');
        assert.ok('attackerUtility' in result, 'missing attackerUtility');
    });

    it('advances timestep by 1 each call', () => {
        const config = createSimConfig();
        const state = initSimulation(config);

        assert.equal(state.timestep, 0);
        stepSimulation(state);
        assert.equal(state.timestep, 1);
        stepSimulation(state);
        assert.equal(state.timestep, 2);
    });

    it('step result contains valid utility numbers', () => {
        const state = initSimulation(createSimConfig());
        const result = stepSimulation(state);

        assert.ok(isFinite(result.defenderUtility));
        assert.ok(isFinite(result.attackerUtility));
        assert.ok(isFinite(state.cumulativeDefenderUtility));
    });
});

// ─── Full Episode Execution ────────────────────────────────────────────────

describe('runEpisode', () => {
    it('completes without error and returns final state', () => {
        const config = createSimConfig({ maxSteps: 10 });
        const rlAgent = createAgent();
        const finalState = runEpisode(config, rlAgent);

        assert.equal(finalState.gameOver, true);
        assert.ok(finalState.timestep > 0);
        assert.ok(finalState.history.length > 0);
    });

    it('final state has metrics object', () => {
        const finalState = runEpisode(createSimConfig({ maxSteps: 5 }));

        assert.ok(finalState.metrics);
        assert.ok('detectionRate' in finalState.metrics);
        assert.ok('preventionRate' in finalState.metrics);
        assert.ok('avgDefenderUtility' in finalState.metrics);
        assert.ok('avgAttackerUtility' in finalState.metrics);
    });

    it('cumulative utilities are numeric and finite', () => {
        const finalState = runEpisode(createSimConfig({ maxSteps: 5 }));

        assert.ok(isFinite(finalState.cumulativeDefenderUtility));
        assert.ok(isFinite(finalState.cumulativeAttackerUtility));
    });
});

// ─── Training & Configuration ──────────────────────────────────────────────

describe('runTraining', () => {
    it('training over 5 episodes completes without error', () => {
        const config = createSimConfig({ maxSteps: 5 });
        const rlAgent = createAgent();

        // Mock progress callback
        let callbackCount = 0;
        const cb = () => { callbackCount++; };

        const finalResult = runTraining(config, 5, rlAgent, cb);

        assert.ok(finalResult.agent.episodeCount > 0);
        assert.equal(callbackCount, 1); // Called once (when ep === 0)
    });
});

describe('Config Validation', () => {
    it('all 4 attacker types simulate without error', () => {
        for (const type of ATTACKER_TYPES) {
            const config = createSimConfig({ attackerType: type, maxSteps: 3 });
            const finalState = runEpisode(config);
            assert.equal(finalState.gameOver, true);
            assert.equal(finalState.config.attackerType, type);
        }
    });
});
