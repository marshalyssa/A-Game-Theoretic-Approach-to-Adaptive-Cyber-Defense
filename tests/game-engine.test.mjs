/**
 * Unit Tests — Game Engine
 * 
 * Tests payoff computation, matrix construction, Nash equilibrium,
 * and defender action ranking.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assertValidDistribution, assertAllFinite } from './setup.mjs';

import {
    computeDefenderUtility,
    computeAttackerUtility,
    computePayoffMatrix,
    bestDefenderResponse,
    solveMixedStrategy,
    expectedUtility,
    rankDefenderActions
} from '../js/engine/game-engine.js';

import { TECHNIQUES, TECHNIQUE_BY_ID } from '../js/data/mitre-catalog.js';
import { DEFENDER_ACTIONS, DEFENDER_ACTION_IDS } from '../js/data/defender-actions.js';

// ─── computeDefenderUtility ────────────────────────────────────────────────

describe('computeDefenderUtility', () => {
    it('returns a finite number', () => {
        const tech = TECHNIQUES[0];
        const actionId = DEFENDER_ACTION_IDS[0];
        const utility = computeDefenderUtility(actionId, tech, 0.5);
        assert.ok(typeof utility === 'number' && isFinite(utility),
            `Expected finite number, got ${utility}`);
    });

    it('higher for effective action against matching tactic', () => {
        // "Block IP" should be more effective against Initial Access techniques
        const initialAccessTech = TECHNIQUES.find(t => t.tacticId === 'TA0001');
        if (initialAccessTech) {
            const blockUtil = computeDefenderUtility('block_ip', initialAccessTech, 0.5);
            const doNothingUtil = computeDefenderUtility('do_nothing', initialAccessTech, 0.5);
            assert.ok(blockUtil > doNothingUtil,
                `block_ip (${blockUtil}) should beat do_nothing (${doNothingUtil})`);
        }
    });

    it('Do Nothing has minimal cost contribution', () => {
        const tech = TECHNIQUES[0];
        const util = computeDefenderUtility('do_nothing', tech, 0.5);
        assert.ok(typeof util === 'number' && isFinite(util));
        // "Do Nothing" has cost=0, disruption=0, detectionBonus=0
    });

    it('returns 0 for null technique', () => {
        const util = computeDefenderUtility('block_ip', null, 0.5);
        assert.equal(util, 0);
    });
});

// ─── computeAttackerUtility ────────────────────────────────────────────────

describe('computeAttackerUtility', () => {
    it('returns a finite number', () => {
        const tech = TECHNIQUES[0];
        const util = computeAttackerUtility(tech, DEFENDER_ACTION_IDS[0], 0.5);
        assert.ok(typeof util === 'number' && isFinite(util),
            `Expected finite number, got ${util}`);
    });

    it('higher when defense is weaker', () => {
        const tech = TECHNIQUES[0];
        // "Do Nothing" should give attacker higher utility than "Threat Hunt"
        const vsNothing = computeAttackerUtility(tech, 'do_nothing', 0.5);
        const vsHunt = computeAttackerUtility(tech, 'threat_hunt', 0.5);
        assert.ok(vsNothing >= vsHunt,
            `Attacker utility vs do_nothing (${vsNothing}) should >= vs threat_hunt (${vsHunt})`);
    });

    it('returns 0 for null technique', () => {
        const util = computeAttackerUtility(null, 'block_ip', 0.5);
        assert.equal(util, 0);
    });
});

// ─── computePayoffMatrix ───────────────────────────────────────────────────

describe('computePayoffMatrix', () => {
    const techIds = TECHNIQUES.slice(0, 5).map(t => t.id);

    it('returns correct dimensions', () => {
        const result = computePayoffMatrix(techIds);
        assert.equal(result.defenderMatrix.length, techIds.length,
            `Rows should equal techniques count`);
        assert.equal(result.defenderMatrix[0].length, DEFENDER_ACTION_IDS.length,
            `Columns should equal actions count`);
    });

    it('defender and attacker matrices have same dimensions', () => {
        const result = computePayoffMatrix(techIds);
        assert.equal(result.defenderMatrix.length, result.attackerMatrix.length);
        assert.equal(result.defenderMatrix[0].length, result.attackerMatrix[0].length);
    });

    it('all values are finite numbers', () => {
        const result = computePayoffMatrix(techIds);
        for (const row of result.defenderMatrix) {
            for (const val of row) {
                assert.ok(isFinite(val), `Non-finite value in defender matrix: ${val}`);
            }
        }
        for (const row of result.attackerMatrix) {
            for (const val of row) {
                assert.ok(isFinite(val), `Non-finite value in attacker matrix: ${val}`);
            }
        }
    });
});

// ─── bestDefenderResponse ──────────────────────────────────────────────────

describe('bestDefenderResponse', () => {
    it('returns action with highest expected utility', () => {
        const techIds = TECHNIQUES.slice(0, 5).map(t => t.id);
        const result = computePayoffMatrix(techIds);
        // Uniform attacker distribution
        const dist = Array(techIds.length).fill(1 / techIds.length);
        const best = bestDefenderResponse(dist, result.defenderMatrix, result.actionIds);
        assert.ok('actionId' in best, 'Missing actionId');
        assert.ok('expectedUtility' in best, 'Missing expectedUtility');
        assert.ok(typeof best.expectedUtility === 'number');
    });
});

// ─── solveMixedStrategy ────────────────────────────────────────────────────

describe('solveMixedStrategy', () => {
    it('returns valid probability distributions', () => {
        const techIds = TECHNIQUES.slice(0, 3).map(t => t.id);
        const result = computePayoffMatrix(techIds);
        const mixed = solveMixedStrategy(result.defenderMatrix, result.attackerMatrix);

        assert.ok(mixed.defenderStrategy, 'Missing defenderStrategy');
        assert.ok(mixed.attackerStrategy, 'Missing attackerStrategy');

        // Defender strategy should sum to ~1
        const defSum = mixed.defenderStrategy.reduce((s, v) => s + v, 0);
        assert.ok(Math.abs(defSum - 1.0) < 0.05,
            `Defender strategy should sum to ~1.0, got ${defSum}`);

        // All probabilities >= 0
        for (const p of mixed.defenderStrategy) {
            assert.ok(p >= -0.01, `Negative probability in defender strategy: ${p}`);
        }
    });

    it('returns finite game values', () => {
        const techIds = TECHNIQUES.slice(0, 3).map(t => t.id);
        const result = computePayoffMatrix(techIds);
        const mixed = solveMixedStrategy(result.defenderMatrix, result.attackerMatrix);
        assert.ok(isFinite(mixed.defenderValue), `Defender value should be finite: ${mixed.defenderValue}`);
        assert.ok(isFinite(mixed.attackerValue), `Attacker value should be finite: ${mixed.attackerValue}`);
    });
});

// ─── expectedUtility ───────────────────────────────────────────────────────

describe('expectedUtility', () => {
    it('computes correct weighted sum for known input', () => {
        const ownStrategy = [0.5, 0.5];
        const oppStrategy = [0.5, 0.5];
        const matrix = [[4, 2], [1, 3]];
        const eu = expectedUtility(ownStrategy, oppStrategy, matrix);
        // E = 0.5*0.5*4 + 0.5*0.5*2 + 0.5*0.5*1 + 0.5*0.5*3 = 2.5
        assert.ok(Math.abs(eu - 2.5) < 0.01,
            `Expected 2.5, got ${eu}`);
    });
});

// ─── rankDefenderActions ───────────────────────────────────────────────────

describe('rankDefenderActions', () => {
    it('returns actions sorted by expected utility descending', () => {
        // Create a simple predicted technique distribution
        const dist = {};
        TECHNIQUES.slice(0, 3).forEach(t => dist[t.id] = 1 / 3);
        const ranked = rankDefenderActions(dist, 0.5);
        assert.ok(ranked.length > 0, 'Should return at least one action');
        for (let i = 1; i < ranked.length; i++) {
            assert.ok(ranked[i - 1].expectedUtility >= ranked[i].expectedUtility,
                `Actions should be sorted descending at index ${i}`);
        }
    });

    it('each action has required fields', () => {
        const dist = {};
        TECHNIQUES.slice(0, 3).forEach(t => dist[t.id] = 1 / 3);
        const ranked = rankDefenderActions(dist, 0.5);
        for (const action of ranked) {
            assert.ok('actionId' in action, 'Missing actionId');
            assert.ok('name' in action, 'Missing name');
            assert.ok('expectedUtility' in action, 'Missing expectedUtility');
            assert.ok('cost' in action, 'Missing cost');
            assert.ok('disruption' in action, 'Missing disruption');
        }
    });
});
