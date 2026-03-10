/**
 * Unit Tests — RL Agent
 * 
 * Tests the Q-learning agent creation, action selection (epsilon-greedy),
 * Q-table updates, and epsilon decay.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    createAgent,
    selectAction,
    updateAgent,
    decayEpsilon,
    getAgentStats,
    resetAgent
} from '../js/engine/rl-agent.js';

import { DEFENDER_ACTION_IDS } from '../js/data/defender-actions.js';

// ─── createAgent ──────────────────────────────────────────────────────────

describe('createAgent', () => {
    it('returns agent with correct default config', () => {
        const agent = createAgent();
        assert.equal(agent.alpha, 0.1);
        assert.equal(agent.gamma, 0.95);
        assert.equal(agent.epsilon, 0.3);
        assert.equal(typeof agent.qTable, 'object');
    });

    it('custom config overrides defaults', () => {
        const custom = { alpha: 0.5, epsilon: 0.9, epsilonMin: 0.1 };
        const agent = createAgent(custom);
        assert.equal(agent.alpha, 0.5);
        assert.equal(agent.epsilon, 0.9);
        assert.equal(agent.epsilonMin, 0.1);
        // Untouched defaults should remain
        assert.equal(agent.gamma, 0.95);
    });
});

// ─── selectAction ─────────────────────────────────────────────────────────

describe('selectAction', () => {
    const mockState = {
        tacticPhase: 1,
        belief: { script_kiddie: 0.25, organized_crime: 0.25, apt_state: 0.25, insider_threat: 0.25 },
        severity: 1,
        criticality: 2,
        lastActionIdx: 0
    };

    it('returns valid action identifier/index', () => {
        const agent = createAgent();
        const result = selectAction(agent, mockState);
        assert.ok(typeof result.actionIdx === 'number');
        assert.ok(typeof result.actionId === 'string');
        assert.ok(DEFENDER_ACTION_IDS.length > 0);
        assert.ok(result.actionIdx >= 0 && result.actionIdx < DEFENDER_ACTION_IDS.length,
            `Action index ${result.actionIdx} out of bounds`);
    });

    it('with epsilon=1.0, always explores (random)', () => {
        const agent = createAgent({ epsilon: 1.0 });
        const selectedActions = new Set();
        // Over many calls, should pick multiple different actions
        for (let i = 0; i < 100; i++) {
            selectedActions.add(selectAction(agent, mockState));
        }
        assert.ok(selectedActions.size > 1, `Should explore multiple actions, got ${selectedActions.size}`);
    });

    it('with epsilon=0.0, always exploits (greedy)', () => {
        const agent = createAgent({ epsilon: 0.0 });
        const action1 = selectAction(agent, mockState);
        const action2 = selectAction(agent, mockState);
        const action3 = selectAction(agent, mockState);
        assert.deepEqual(action1, action2);
        assert.deepEqual(action2, action3);
    });
});

// ─── updateAgent ──────────────────────────────────────────────────────────

describe('updateAgent', () => {
    const mockState = { tacticPhase: 1, belief: { script_kiddie: 0.25, organized_crime: 0.25, apt_state: 0.25, insider_threat: 0.25 }, severity: 1, criticality: 2, lastActionIdx: 0 };
    const nextState = { tacticPhase: 2, belief: { script_kiddie: 0.25, organized_crime: 0.25, apt_state: 0.25, insider_threat: 0.25 }, severity: 1, criticality: 2, lastActionIdx: 0 };

    it('Q-value changes after update (positive reward)', () => {
        const agent = createAgent({ alpha: 0.5 });
        // Initial Q should be 0
        updateAgent(agent, mockState, 0, 10, nextState, false);
        const stats = getAgentStats(agent);
        assert.ok(stats.qTableStates > 0, 'Q-table should have states');
        // We test statistically - we know Q-value must be > 0
        const stateStr = '1_0_1_2_0'; // expected state string format from rl-agent.js
        assert.ok(agent.qTable[stateStr] !== undefined);
        assert.ok(agent.qTable[stateStr][0] > 0, 'Q-value should increase for positive reward');
    });

    it('Q(s,a) moves toward reward when done=true (terminal state)', () => {
        const agent = createAgent({ alpha: 1.0 }); // 1.0 means full update to target
        updateAgent(agent, mockState, 1, 5, nextState, true);
        const stateStr = '1_0_1_2_0';
        // With alpha=1 and done=true, Q(s,a) = reward = 5
        assert.ok(Math.abs(agent.qTable[stateStr][1] - 5) < 0.001);
    });
});

// ─── decayEpsilon ─────────────────────────────────────────────────────────

describe('decayEpsilon', () => {
    it('epsilon decreases but stays above epsilon_min', () => {
        const agent = createAgent({ epsilon: 0.5, epsilonDecay: 0.9, epsilonMin: 0.1 });
        const initial = agent.epsilon;

        decayEpsilon(agent);
        assert.ok(agent.currentEpsilon < initial, `Epsilon ${agent.currentEpsilon} should be < ${initial}`);

        // Decay many times to hit minimum
        for (let i = 0; i < 50; i++) decayEpsilon(agent);
        assert.ok(agent.currentEpsilon >= agent.epsilonMin,
            `Epsilon ${agent.currentEpsilon} dropped below min ${agent.epsilonMin}`);
    });
});

// ─── getAgentStats ────────────────────────────────────────────────────────

describe('getAgentStats', () => {
    it('returns required statistics fields', () => {
        const agent = createAgent();
        const stats = getAgentStats(agent);
        assert.ok('episodes' in stats);
        assert.ok('currentEpsilon' in stats);
        assert.ok('qTableStates' in stats);
        assert.ok('avgReward' in stats);
        assert.equal(stats.episodes, 0);
    });
});

// ─── resetAgent ───────────────────────────────────────────────────────────

describe('resetAgent', () => {
    it('clears Q-table but preserves config', () => {
        const customConfig = { alpha: 0.8, epsilon: 0.5 };
        const agent = createAgent(customConfig);

        const mockState = { tacticPhase: 1, belief: { script_kiddie: 0.25, organized_crime: 0.25, apt_state: 0.25, insider_threat: 0.25 }, severity: 1, criticality: 2, lastActionIdx: 0 };
        updateAgent(agent, mockState, 0, 10, mockState, false);

        assert.ok(Object.keys(agent.qTable).length > 0);

        resetAgent(agent);
        assert.equal(Object.keys(agent.qTable).length, 0);
        assert.equal(agent.alpha, 0.8);
        assert.equal(agent.epsilon, customConfig.epsilon); // should reset to initial epsilon
    });
});
