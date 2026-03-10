/**
 * Unit Tests — Bayesian Engine
 * 
 * Tests the Bayesian belief update, entropy, prediction, and decay logic.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { assertValidDistribution, assertAllFinite } from './setup.mjs';

import {
    createBeliefState,
    updateBelief,
    updateBeliefBatch,
    decayBelief,
    getBeliefEntropy,
    getMaxEntropy,
    getMostProbableType,
    predictNextTechnique,
    getTopPredictions
} from '../js/engine/bayesian-engine.js';

import { ATTACKER_TYPES } from '../js/data/attacker-profiles.js';
import { TECHNIQUES } from '../js/data/mitre-catalog.js';

// ─── createBeliefState ─────────────────────────────────────────────────────

describe('createBeliefState', () => {
    it('returns uniform distribution by default', () => {
        const belief = createBeliefState();
        const expected = 1 / ATTACKER_TYPES.length;
        for (const type of ATTACKER_TYPES) {
            assert.ok(Math.abs(belief[type] - expected) < 0.001,
                `${type} should be ~${expected}, got ${belief[type]}`);
        }
    });

    it('has all attacker types as keys', () => {
        const belief = createBeliefState();
        for (const type of ATTACKER_TYPES) {
            assert.ok(type in belief, `Missing key: ${type}`);
        }
    });

    it('normalizes custom prior correctly', () => {
        const prior = {};
        ATTACKER_TYPES.forEach((t, i) => prior[t] = i + 1);
        const belief = createBeliefState(prior);
        const sum = Object.values(belief).reduce((s, v) => s + v, 0);
        assert.ok(Math.abs(sum - 1.0) < 0.001, `Sum should be ~1.0, got ${sum}`);
    });

    it('returns uniform when prior sums to zero', () => {
        const prior = {};
        ATTACKER_TYPES.forEach(t => prior[t] = 0);
        const belief = createBeliefState(prior);
        const expected = 1 / ATTACKER_TYPES.length;
        for (const type of ATTACKER_TYPES) {
            assert.ok(Math.abs(belief[type] - expected) < 0.001);
        }
    });
});

// ─── updateBelief ──────────────────────────────────────────────────────────

describe('updateBelief', () => {
    it('shifts belief toward correct type after type-specific technique', () => {
        const belief = createBeliefState();
        // T1110 Brute Force — commonly used by script kiddies
        const updated = updateBelief(belief, 'T1110');
        // The most probable type should have higher probability than uniform
        const best = getMostProbableType(updated);
        assert.ok(best.probability > 1 / ATTACKER_TYPES.length,
            `Best type ${best.type} should be > uniform, got ${best.probability}`);
    });

    it('maintains valid probability distribution after update', () => {
        const belief = createBeliefState();
        const updated = updateBelief(belief, 'T1595');
        assertValidDistribution(updated);
    });

    it('decreases entropy after observing informative technique', () => {
        const belief = createBeliefState();
        const h0 = getBeliefEntropy(belief);
        const updated = updateBelief(belief, 'T1110');
        const h1 = getBeliefEntropy(updated);
        assert.ok(h1 <= h0, `Entropy should decrease: ${h0} → ${h1}`);
    });

    it('multiple updates converge belief (entropy decreases)', () => {
        let belief = createBeliefState();
        const entropies = [getBeliefEntropy(belief)];
        // Observe several techniques associated with script kiddie
        for (const tech of ['T1110', 'T1595', 'T1190']) {
            belief = updateBelief(belief, tech);
            entropies.push(getBeliefEntropy(belief));
        }
        // Final entropy should be less than initial
        assert.ok(entropies[entropies.length - 1] < entropies[0],
            `Entropy should decrease over observations: ${entropies}`);
    });
});

// ─── updateBeliefBatch ─────────────────────────────────────────────────────

describe('updateBeliefBatch', () => {
    it('produces same result as sequential updates', () => {
        const techniques = ['T1595', 'T1110', 'T1190'];

        // Sequential
        let sequential = createBeliefState();
        for (const tech of techniques) {
            sequential = updateBelief(sequential, tech);
        }

        // Batch
        const batch = updateBeliefBatch(createBeliefState(), techniques);

        for (const type of ATTACKER_TYPES) {
            assert.ok(Math.abs(sequential[type] - batch[type]) < 0.001,
                `${type}: sequential=${sequential[type]}, batch=${batch[type]}`);
        }
    });
});

// ─── decayBelief ───────────────────────────────────────────────────────────

describe('decayBelief', () => {
    it('moves belief toward uniform distribution', () => {
        // Start with concentrated belief
        let belief = createBeliefState();
        belief = updateBelief(belief, 'T1110');
        belief = updateBelief(belief, 'T1110');

        const before = { ...belief };
        const decayed = decayBelief(belief, 0.1);
        const uniform = 1 / ATTACKER_TYPES.length;

        for (const type of ATTACKER_TYPES) {
            const distBefore = Math.abs(before[type] - uniform);
            const distAfter = Math.abs(decayed[type] - uniform);
            assert.ok(distAfter <= distBefore + 0.001,
                `${type} should move toward uniform`);
        }
    });

    it('with rate=0 returns original belief', () => {
        const belief = createBeliefState();
        const decayed = decayBelief(belief, 0);
        for (const type of ATTACKER_TYPES) {
            assert.ok(Math.abs(belief[type] - decayed[type]) < 0.001);
        }
    });
});

// ─── getBeliefEntropy ──────────────────────────────────────────────────────

describe('getBeliefEntropy', () => {
    it('uniform distribution gives max entropy ≈ 2.0', () => {
        const belief = createBeliefState();
        const entropy = getBeliefEntropy(belief);
        const maxE = getMaxEntropy();
        assert.ok(Math.abs(entropy - maxE) < 0.01,
            `Uniform entropy should be ~${maxE}, got ${entropy}`);
    });

    it('near-certain distribution gives entropy close to 0', () => {
        const belief = {};
        ATTACKER_TYPES.forEach((t, i) => belief[t] = i === 0 ? 0.97 : 0.01);
        const entropy = getBeliefEntropy(belief);
        assert.ok(entropy < 0.5, `Near-certain entropy should be < 0.5, got ${entropy}`);
    });
});

// ─── getMostProbableType ───────────────────────────────────────────────────

describe('getMostProbableType', () => {
    it('returns correct type and probability', () => {
        const belief = {};
        ATTACKER_TYPES.forEach((t, i) => belief[t] = i === 2 ? 0.7 : 0.1);
        const result = getMostProbableType(belief);
        assert.equal(result.type, ATTACKER_TYPES[2]);
        assert.ok(Math.abs(result.probability - 0.7) < 0.01);
    });
});

// ─── predictNextTechnique ──────────────────────────────────────────────────

describe('predictNextTechnique', () => {
    it('returns normalized distribution', () => {
        const belief = createBeliefState();
        const techId = TECHNIQUES[0].id; // First technique in catalog
        const prediction = predictNextTechnique(belief, techId);
        const sum = Object.values(prediction).reduce((s, v) => s + v, 0);
        // Sum should be ~1.0 (or 0 if no transitions exist)
        assert.ok(sum < 0.01 || Math.abs(sum - 1.0) < 0.05,
            `Prediction should sum to ~1 or ~0, got ${sum}`);
    });

    it('returns all non-negative values', () => {
        const belief = createBeliefState();
        const techId = TECHNIQUES[0].id;
        const prediction = predictNextTechnique(belief, techId);
        for (const [id, prob] of Object.entries(prediction)) {
            assert.ok(prob >= 0, `Technique ${id} has negative probability: ${prob}`);
        }
    });
});

// ─── getTopPredictions ─────────────────────────────────────────────────────

describe('getTopPredictions', () => {
    it('returns N items sorted by probability descending', () => {
        const belief = createBeliefState();
        const techId = TECHNIQUES[0].id;
        const top = getTopPredictions(belief, techId, 3);
        assert.ok(top.length <= 3, `Should return at most 3 items, got ${top.length}`);
        for (let i = 1; i < top.length; i++) {
            assert.ok(top[i - 1].probability >= top[i].probability,
                `Items should be sorted descending at index ${i}`);
        }
    });

    it('each prediction has required fields', () => {
        const belief = createBeliefState();
        const techId = TECHNIQUES[0].id;
        const top = getTopPredictions(belief, techId, 5);
        for (const pred of top) {
            assert.ok('id' in pred, 'Missing id field');
            assert.ok('name' in pred, 'Missing name field');
            assert.ok('probability' in pred, 'Missing probability field');
            assert.ok('tacticId' in pred, 'Missing tacticId field');
        }
    });
});
