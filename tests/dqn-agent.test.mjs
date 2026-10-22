import { test, describe } from 'node:test';
import * as assert from 'node:assert';

// Mock DOM environment if needed by imports (though dqn-agent should be pure JS)
import './setup.mjs';

import { NeuralNetwork, ReplayBuffer, createDQNAgent, selectDQNAction, updateDQNAgent, stateToVector, trainDQNBatch, syncTargetNetwork, stateKeyToVector, trainFromIOCReplay } from '../js/engine/dqn-agent.js';
import { DEFENDER_ACTION_IDS } from '../js/data/defender-actions.js';

describe('Neural Network', () => {
    test('Initialization', () => {
        const net = new NeuralNetwork([9, 64, 15], 0.01);
        assert.equal(net.weights.length, 2);
        assert.equal(net.biases.length, 2);
        assert.equal(net.weights[0].length, 64);
        assert.equal(net.weights[0][0].length, 9);
    });

    test('Forward pass', () => {
        const net = new NeuralNetwork([3, 4, 2]);
        const output = net.forward([0.5, -0.2, 0.1]);
        assert.equal(output.length, 2);
        assert.ok(output.every(v => typeof v === 'number' && !isNaN(v)));
    });

    test('Backward pass', () => {
        const net = new NeuralNetwork([3, 4, 2], 0.1);
        const input = [1, 0, -1];
        const initialOutput = net.forward(input);
        
        // Target: move output[0] towards 10
        const targets = [...initialOutput];
        targets[0] = 10;
        
        const loss = net.backward(targets, 0);
        assert.ok(loss > 0);
        
        const newOutput = net.forward(input);
        // The new output[0] should be closer to 10 than the initial
        assert.ok(Math.abs(newOutput[0] - 10) < Math.abs(initialOutput[0] - 10));
    });
});

describe('Replay Buffer', () => {
    test('Push and Sample', () => {
        const buffer = new ReplayBuffer(10);
        assert.equal(buffer.size, 0);
        
        for (let i = 0; i < 5; i++) {
            buffer.push([i], i, 1, [i+1], false);
        }
        assert.equal(buffer.size, 5);
        
        const batch = buffer.sample(3);
        assert.equal(batch.length, 3);
        assert.ok(batch[0].state !== undefined);
    });
    
    test('Capacity limit', () => {
        const buffer = new ReplayBuffer(3);
        buffer.push([1], 0, 1, [2], false);
        buffer.push([2], 0, 1, [3], false);
        buffer.push([3], 0, 1, [4], false);
        buffer.push([4], 0, 1, [5], false); // Overwrite index 0
        
        assert.equal(buffer.size, 3);
        assert.deepEqual(buffer.buffer[0].state, [4]);
    });
});

describe('DQN Agent encoding', () => {
    test('stateToVector', () => {
        const state = {
            tacticPhase: 0,
            belief: { 'apt_state': 1.0 },
            severity: 2,
            criticality: 2,
            lastActionIdx: 1
        };
        const vec = stateToVector(state);
        assert.equal(vec.length, 9);
        assert.equal(vec[0], 0); // Phase 0
        assert.equal(vec[3], 1.0); // apt_state belief
        assert.equal(vec[5], 1.0); // severity 2 -> normalized to 1.0
        assert.equal(vec[6], 1.0); // criticality 2 -> normalized to 1.0
        assert.ok(vec[8] === 0); // Entropy should be 0 because 100% belief
    });
});

describe('DQN Agent lifecycle', () => {
    test('Initialization', () => {
        const agent = createDQNAgent({ batchSize: 32 });
        assert.equal(agent.type, 'dqn');
        assert.equal(agent.numActions, DEFENDER_ACTION_IDS.length);
        assert.ok(agent.network instanceof NeuralNetwork);
        assert.ok(agent.targetNetwork instanceof NeuralNetwork);
    });

    test('Action Selection (Exploration)', () => {
        const agent = createDQNAgent({ epsilon: 1.0 }); // 100% exploration
        const action = selectDQNAction(agent, { belief: {} });
        assert.ok(action.isExploration);
        assert.ok(action.actionIdx >= 0 && action.actionIdx < DEFENDER_ACTION_IDS.length);
    });

    test('Action Selection (Exploitation)', () => {
        const agent = createDQNAgent({ epsilon: 0.0 }); // 0% exploration
        const action = selectDQNAction(agent, { belief: {} });
        assert.equal(action.isExploration, false);
    });

    test('Update and train', () => {
        const agent = createDQNAgent({ batchSize: 2 });
        const state1 = { tacticPhase: 0, belief: {}, severity: 1, criticality: 1, lastActionIdx: 0 };
        const state2 = { tacticPhase: 1, belief: {}, severity: 1, criticality: 1, lastActionIdx: 1 };
        
        // Push 1 item, shouldn't train yet
        updateDQNAgent(agent, state1, 0, 10, state2, false);
        assert.equal(agent.replayBuffer.size, 1);
        assert.equal(agent.trainingLoss.length, 0);
        
        // Push 2nd item, should trigger training batch
        updateDQNAgent(agent, state2, 1, -5, state1, true);
        assert.equal(agent.replayBuffer.size, 2);
        assert.equal(agent.trainingLoss.length, 1); // Triggers training
        assert.ok(agent.trainingLoss[0] >= 0);
    });
});

// ─── stateKeyToVector ────────────────────────────────────────────────────

describe('stateKeyToVector', () => {
    test('produces 9-dimensional vector', () => {
        const vec = stateKeyToVector('3_15_2_1_0');
        assert.equal(vec.length, 9);
        assert.ok(vec.every(v => typeof v === 'number' && !isNaN(v)));
    });

    test('normalizes phase to [0, 1]', () => {
        const vec0 = stateKeyToVector('0_0_1_1_0');
        const vec13 = stateKeyToVector('13_0_1_1_0');
        assert.equal(vec0[0], 0);
        assert.equal(vec13[0], 1);
    });

    test('handles missing fields gracefully', () => {
        const vec = stateKeyToVector('3');
        assert.equal(vec.length, 9);
        assert.ok(vec.every(v => typeof v === 'number' && !isNaN(v)));
    });

    test('belief components sum to ~1.0', () => {
        const vec = stateKeyToVector('5_10_1_1_2');
        const beliefSum = vec[1] + vec[2] + vec[3] + vec[4];
        assert.ok(Math.abs(beliefSum - 1.0) < 0.01, `Belief sum ${beliefSum} should be ~1.0`);
    });
});

// ─── trainFromIOCReplay ──────────────────────────────────────────────────

describe('trainFromIOCReplay', () => {
    test('returns zero stats for empty experiences', () => {
        const agent = createDQNAgent();
        const result = trainFromIOCReplay(agent, []);
        assert.equal(result.updatesApplied, 0);
        assert.equal(result.avgLoss, 0);
    });

    test('loads experiences into replay buffer', () => {
        const agent = createDQNAgent({ batchSize: 2 });
        const exps = [
            { stateKey: '3_5_2_1_0', actionIdx: 0, reward: 1.5, nextStateKey: '4_5_2_1_0', done: false },
            { stateKey: '4_5_2_1_0', actionIdx: 2, reward: -0.5, nextStateKey: '5_5_2_1_0', done: false },
            { stateKey: '5_5_2_1_0', actionIdx: 1, reward: 2.0, nextStateKey: null, done: true },
        ];
        const result = trainFromIOCReplay(agent, exps, 1);
        assert.ok(result.bufferSize >= 3, 'Buffer should have loaded experiences');
        assert.ok(result.updatesApplied > 0, 'Should have applied training updates');
        assert.ok(typeof result.avgLoss === 'number');
    });

    test('handles snake_case DB field names', () => {
        const agent = createDQNAgent({ batchSize: 2 });
        const exps = [
            { state_key: '1_10_1_1_0', action_idx: 0, reward: 1.0, next_state_key: '2_10_1_1_0', done: 0 },
            { state_key: '2_10_1_1_0', action_idx: 1, reward: 0.5, next_state_key: '3_10_1_1_0', done: 0 },
            { state_key: '3_10_1_1_0', action_idx: 0, reward: 2.0, next_state_key: null, done: 1 },
        ];
        const result = trainFromIOCReplay(agent, exps, 1);
        assert.ok(result.bufferSize >= 3);
    });

    test('multi-epoch training decays epsilon', () => {
        const agent = createDQNAgent({ batchSize: 2, epsilon: 0.5 });
        const initialEps = agent.currentEpsilon;
        const exps = [
            { stateKey: '0_5_1_1_0', actionIdx: 0, reward: 1.0, nextStateKey: '1_5_1_1_0', done: false },
            { stateKey: '1_5_1_1_0', actionIdx: 1, reward: 2.0, nextStateKey: '2_5_1_1_0', done: false },
            { stateKey: '2_5_1_1_0', actionIdx: 2, reward: 3.0, nextStateKey: null, done: true },
        ];
        trainFromIOCReplay(agent, exps, 3);
        assert.ok(agent.currentEpsilon < initialEps, 'Epsilon should decay after training epochs');
    });
});
