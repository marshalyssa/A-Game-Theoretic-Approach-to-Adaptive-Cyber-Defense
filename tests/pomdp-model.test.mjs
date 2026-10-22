import { test, describe } from 'node:test';
import * as assert from 'node:assert';

import './setup.mjs';

import { getTransitionProbabilities, getObservationModel, getExpectedReward, solveQMDPOneStep } from '../js/engine/pomdp-model.js';
import { TACTIC_PHASES } from '../js/data/mitre-catalog.js';
import { DEFENDER_ACTION_IDS } from '../js/data/defender-actions.js';

describe('POMDP Model', () => {
    test('Transition Probabilities', () => {
        // Tactic phase 0
        const trans = getTransitionProbabilities('apt_state', 0, 'isolate');
        assert.equal(trans.length, 2);
        
        let sum = 0;
        for (const t of trans) {
            sum += t.prob;
            if (t.nextPhase === 1) {
                assert.ok(t.done === false);
            } else if (t.nextPhase === 0) {
                assert.ok(t.done === true);
            }
        }
        assert.ok(Math.abs(sum - 1.0) < 0.001);

        // Terminal phase
        const transTerminal = getTransitionProbabilities('apt_state', TACTIC_PHASES.length - 1, 'monitor');
        assert.equal(transTerminal.length, 1);
        assert.equal(transTerminal[0].prob, 1.0);
        assert.ok(transTerminal[0].done === true);
    });

    test('Observation Model', () => {
        const obs = getObservationModel('script_kiddie', 0, 0.5);
        let sum = 0;
        for (const [key, prob] of Object.entries(obs)) {
            sum += prob;
        }
        assert.ok(Math.abs(sum - 1.0) < 0.001);
        assert.ok(obs['none'] !== undefined);
        
        // Zero detection should mean 100% 'none'
        const obsZero = getObservationModel('apt_state', 0, 0.0);
        assert.ok(Math.abs(obsZero['none'] - 1.0) < 0.001);
    });

    test('Expected Reward', () => {
        const reward = getExpectedReward('apt_state', 0, 'monitor', 0.8);
        assert.ok(typeof reward === 'number');
        assert.ok(!isNaN(reward));
    });

    test('Q-MDP 1-Step Lookahead Solver', () => {
        const belief = { 'apt_state': 0.8, 'script_kiddie': 0.2 };
        const result = solveQMDPOneStep(belief, 0, 0.5);
        assert.ok(result.bestAction);
        assert.ok(DEFENDER_ACTION_IDS.includes(result.bestAction));
        assert.ok(result.qValues[result.bestAction] !== undefined);
    });
});
