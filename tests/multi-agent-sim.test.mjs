import { test, describe } from 'node:test';
import * as assert from 'node:assert';

import './setup.mjs';
import { computeGlobalMultiThreatResponse } from '../js/engine/multi-agent-sim.js';
import { createBeliefState } from '../js/engine/bayesian-engine.js';
import { DEFENDER_ACTION_IDS } from '../js/data/defender-actions.js';

describe('Multi-Agent Live Analysis', () => {
    test('Returns null for empty active threats list', () => {
        const result = computeGlobalMultiThreatResponse([]);
        assert.equal(result, null);
    });

    test('Computes resilient global action for concurrent threats', () => {
        const cluster1 = {
            belief: createBeliefState(),
            killChainCoverage: { 'initial_access': true }
        };
        
        const cluster2 = {
            belief: createBeliefState(),
            killChainCoverage: { 'execution': true }
        };

        const activeSessions = [cluster1, cluster2];
        const result = computeGlobalMultiThreatResponse(activeSessions, 0.5);
        
        assert.ok(result);
        assert.ok(DEFENDER_ACTION_IDS.includes(result.bestGlobalAction));
        assert.equal(result.activeThreatsCount, 2);
        assert.ok(typeof result.globalUtility === 'number');
    });
});
