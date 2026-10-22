/**
 * Deep Q-Network Agent — Neural Network-Based Defender
 * 
 * Replaces tabular Q-learning with a feedforward neural network for
 * function approximation. Handles continuous state spaces without
 * discretization loss.
 * 
 * Training is driven by experience replay from stored IOC analysis data.
 * Live IOC analyses generate (s, a, r, s’, done) tuples which are persisted
 * to SQLite and later replayed through the network for offline learning.
 * 
 * Architecture:
 *   Input:  9 features [tacticPhase(1), belief(4), severity(1), criticality(1), lastActionIdx(1), entropy(1)]
 *   Hidden: 2 layers × 64 neurons, ReLU activation
 *   Output: 15 Q-values (one per defender action)
 * 
 * Features:
 *   - Experience Replay Buffer (circular, uniform sampling)
 *   - Target Network (periodic sync for training stability)
 *   - Epsilon-greedy exploration with annealing
 *   - Offline IOC replay training from DB-format experience tuples
 */

import { DEFENDER_ACTION_IDS } from '../data/defender-actions.js';
import { ATTACKER_TYPES } from '../data/attacker-profiles.js';
import { getBeliefEntropy } from './bayesian-engine.js';

// ═══════════════════════════════════════════════════════════════════════════
//  NEURAL NETWORK (from scratch — no external dependencies)
// ═══════════════════════════════════════════════════════════════════════════

class NeuralNetwork {
    /**
     * @param {number[]} layerSizes - e.g. [9, 64, 64, 15]
     * @param {number} learningRate
     */
    constructor(layerSizes, learningRate = 0.001) {
        this.layerSizes = layerSizes;
        this.lr = learningRate;
        this.weights = [];
        this.biases = [];

        // Xavier initialization
        for (let i = 0; i < layerSizes.length - 1; i++) {
            const fanIn = layerSizes[i];
            const fanOut = layerSizes[i + 1];
            const scale = Math.sqrt(2 / (fanIn + fanOut));
            
            const w = [];
            for (let r = 0; r < fanOut; r++) {
                const row = [];
                for (let c = 0; c < fanIn; c++) {
                    row.push((Math.random() * 2 - 1) * scale);
                }
                w.push(row);
            }
            this.weights.push(w);
            this.biases.push(new Array(fanOut).fill(0));
        }
    }

    /**
     * Forward pass
     * @param {number[]} input
     * @returns {number[]} output Q-values
     */
    forward(input) {
        let activations = input.slice();
        this._layerInputs = [activations.slice()];
        this._preActivations = [];

        for (let l = 0; l < this.weights.length; l++) {
            const w = this.weights[l];
            const b = this.biases[l];
            const output = new Array(w.length);
            
            for (let i = 0; i < w.length; i++) {
                let sum = b[i];
                for (let j = 0; j < w[i].length; j++) {
                    sum += w[i][j] * activations[j];
                }
                output[i] = sum;
            }

            this._preActivations.push(output.slice());

            // ReLU for hidden layers, linear for output
            if (l < this.weights.length - 1) {
                for (let i = 0; i < output.length; i++) {
                    output[i] = Math.max(0, output[i]);
                }
            }

            activations = output;
            this._layerInputs.push(activations.slice());
        }

        return activations;
    }

    /**
     * Backward pass with MSE loss gradient for specific action indices
     * @param {number[]} targetQValues - full target Q vector (only actionIdx matters)
     * @param {number} actionIdx - which action to compute loss for
     * @returns {number} loss for this sample
     */
    backward(targetQValues, actionIdx) {
        const numLayers = this.weights.length;
        const output = this._layerInputs[numLayers];
        
        // Gradient at output: only for the taken action
        let gradients = new Array(output.length).fill(0);
        const error = output[actionIdx] - targetQValues[actionIdx];
        gradients[actionIdx] = error;
        const loss = 0.5 * error * error;

        // Backpropagate through layers
        for (let l = numLayers - 1; l >= 0; l--) {
            const input = this._layerInputs[l];
            const preAct = this._preActivations[l];
            
            // Apply ReLU derivative for hidden layers
            if (l < numLayers - 1) {
                for (let i = 0; i < gradients.length; i++) {
                    gradients[i] = preAct[i] > 0 ? gradients[i] : 0;
                }
            }

            // Compute input gradients for next layer
            const inputGrad = new Array(input.length).fill(0);
            for (let i = 0; i < gradients.length; i++) {
                for (let j = 0; j < input.length; j++) {
                    inputGrad[j] += this.weights[l][i][j] * gradients[i];
                }
            }

            // Update weights and biases with gradient clipping
            for (let i = 0; i < gradients.length; i++) {
                const clippedGrad = Math.max(-1, Math.min(1, gradients[i]));
                this.biases[l][i] -= this.lr * clippedGrad;
                for (let j = 0; j < input.length; j++) {
                    this.weights[l][i][j] -= this.lr * clippedGrad * input[j];
                }
            }

            gradients = inputGrad;
        }

        return loss;
    }

    /**
     * Copy weights from another network
     */
    copyFrom(other) {
        for (let l = 0; l < this.weights.length; l++) {
            for (let i = 0; i < this.weights[l].length; i++) {
                for (let j = 0; j < this.weights[l][i].length; j++) {
                    this.weights[l][i][j] = other.weights[l][i][j];
                }
                this.biases[l][i] = other.biases[l][i];
            }
        }
    }

    /**
     * Export weights for persistence
     */
    toJSON() {
        return {
            layerSizes: this.layerSizes,
            lr: this.lr,
            weights: this.weights,
            biases: this.biases
        };
    }

    /**
     * Import weights from JSON
     */
    static fromJSON(data) {
        const net = new NeuralNetwork(data.layerSizes, data.lr);
        net.weights = data.weights;
        net.biases = data.biases;
        return net;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  EXPERIENCE REPLAY BUFFER
// ═══════════════════════════════════════════════════════════════════════════

class ReplayBuffer {
    /**
     * @param {number} capacity - Maximum experiences to store
     */
    constructor(capacity = 10000) {
        this.capacity = capacity;
        this.buffer = [];
        this.position = 0;
    }

    /**
     * Add experience tuple to buffer
     * @param {number[]} state - state vector
     * @param {number} action - action index
     * @param {number} reward - received reward
     * @param {number[]} nextState - next state vector
     * @param {boolean} done - episode over?
     */
    push(state, action, reward, nextState, done) {
        const exp = { state, action, reward, nextState, done };
        if (this.buffer.length < this.capacity) {
            this.buffer.push(exp);
        } else {
            this.buffer[this.position] = exp;
        }
        this.position = (this.position + 1) % this.capacity;
    }

    /**
     * Sample a random mini-batch
     * @param {number} batchSize
     * @returns {Object[]} batch of experiences
     */
    sample(batchSize) {
        const batch = [];
        const len = this.buffer.length;
        for (let i = 0; i < batchSize; i++) {
            const idx = Math.floor(Math.random() * len);
            batch.push(this.buffer[idx]);
        }
        return batch;
    }

    get size() {
        return this.buffer.length;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  STATE ENCODING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert simulation state into a numeric feature vector
 * @param {Object} state - { tacticPhase, belief, severity, criticality, lastActionIdx }
 * @returns {number[]} 9-dimensional normalized vector
 */
export function stateToVector(state) {
    const belief = state.belief || {};
    const entropy = getBeliefEntropy(belief);
    const maxEntropy = Math.log2(ATTACKER_TYPES.length); // 2.0 bits for 4 types

    return [
        (state.tacticPhase || 0) / 13,                          // Normalize tactic phase [0-13] → [0-1]
        belief[ATTACKER_TYPES[0]] || 0.25,                      // P(script_kiddie)
        belief[ATTACKER_TYPES[1]] || 0.25,                      // P(organized_crime)
        belief[ATTACKER_TYPES[2]] || 0.25,                      // P(apt_state)
        belief[ATTACKER_TYPES[3]] || 0.25,                      // P(insider_threat)
        (state.severity || 1) / 2,                              // Normalize severity [0-2] → [0-1]
        (state.criticality || 1) / 2,                           // Normalize criticality [0-2] → [0-1]
        (state.lastActionIdx || 0) / (DEFENDER_ACTION_IDS.length - 1),  // Normalize action index
        entropy / maxEntropy                                     // Normalized belief entropy [0-1]
    ];
}

/**
 * Convert a DB-format state key string into the 9D feature vector.
 * State key format: "phase_beliefBucket_severity_criticality_lastAction"
 * 
 * Since the DB stores discretized keys (not the full belief distribution),
 * we reconstruct an approximate belief vector from the belief bucket index.
 * 
 * @param {string} stateKey - e.g. "3_15_2_1_0"
 * @returns {number[]} 9-dimensional normalized vector
 */
export function stateKeyToVector(stateKey) {
    const parts = stateKey.split('_').map(Number);
    const phase = parts[0] || 0;
    const beliefBucket = parts[1] || 0;
    const severity = parts[2] || 1;
    const criticality = parts[3] || 1;
    const lastAction = parts[4] || 0;

    // Reconstruct approximate uniform-ish belief from bucket index
    // beliefBucket from live-monitor = Math.round(entropy * 10)
    // Max entropy ~2.0 bits for 4 types, so bucket range is 0-20
    const normalizedEntropy = Math.min(beliefBucket / 20, 1.0);

    // Approximate belief: distribute probability based on entropy level
    // High entropy → uniform (0.25 each), low entropy → concentrated
    const concentration = 1.0 - normalizedEntropy;
    const base = 0.25;
    const beliefs = [
        base - concentration * 0.15,  // script_kiddie
        base - concentration * 0.05,  // organized_crime
        base + concentration * 0.25,  // apt_state (assume high-threat bias)
        base - concentration * 0.05   // insider_threat
    ];
    // Clamp to valid probabilities
    const sum = beliefs.reduce((s, v) => s + Math.max(0, v), 0);
    const normBeliefs = beliefs.map(b => Math.max(0, b) / sum);

    return [
        phase / 13,                                           // tactic phase
        normBeliefs[0],                                       // P(script_kiddie)
        normBeliefs[1],                                       // P(organized_crime)
        normBeliefs[2],                                       // P(apt_state)
        normBeliefs[3],                                       // P(insider_threat)
        severity / 2,                                         // severity
        criticality / 2,                                      // criticality
        lastAction / (DEFENDER_ACTION_IDS.length - 1 || 1),   // last action
        normalizedEntropy                                     // entropy
    ];
}

// ═══════════════════════════════════════════════════════════════════════════
//  DQN AGENT
// ═══════════════════════════════════════════════════════════════════════════

const INPUT_SIZE = 9;
const OUTPUT_SIZE = DEFENDER_ACTION_IDS.length; // 15
const HIDDEN_SIZE = 64;

/**
 * Create a DQN agent
 * @param {Object} config
 * @returns {Object} DQN agent
 */
export function createDQNAgent(config = {}) {
    const epsilon = config.epsilon ?? 0.3;
    const epsilonDecay = config.epsilonDecay ?? 0.995;
    const epsilonMin = config.epsilonMin ?? 0.01;
    const gamma = config.gamma ?? 0.95;
    const batchSize = config.batchSize ?? 32;
    const targetSyncInterval = config.targetSyncInterval ?? 50;
    const learningRate = config.learningRate ?? 0.001;
    const bufferCapacity = config.bufferCapacity ?? 10000;

    const network = new NeuralNetwork([INPUT_SIZE, HIDDEN_SIZE, HIDDEN_SIZE, OUTPUT_SIZE], learningRate);
    const targetNetwork = new NeuralNetwork([INPUT_SIZE, HIDDEN_SIZE, HIDDEN_SIZE, OUTPUT_SIZE], learningRate);
    targetNetwork.copyFrom(network);

    return {
        type: 'dqn',
        network,
        targetNetwork,
        replayBuffer: new ReplayBuffer(bufferCapacity),
        gamma,
        epsilon,
        epsilonDecay,
        epsilonMin,
        currentEpsilon: epsilon,
        batchSize,
        targetSyncInterval,
        numActions: OUTPUT_SIZE,
        episodeCount: 0,
        stepCount: 0,
        totalReward: 0,
        rewardHistory: [],
        trainingLoss: []
    };
}

/**
 * Select an action using ε-greedy over DQN Q-values
 * @param {Object} agent - DQN agent
 * @param {Object} state - simulation state
 * @returns {{ actionIdx, actionId, isExploration }}
 */
export function selectDQNAction(agent, state) {
    const stateVec = stateToVector(state);
    let actionIdx;
    let isExploration = false;

    if (Math.random() < agent.currentEpsilon) {
        actionIdx = Math.floor(Math.random() * agent.numActions);
        isExploration = true;
    } else {
        const qValues = agent.network.forward(stateVec);
        actionIdx = 0;
        let maxQ = qValues[0];
        for (let i = 1; i < qValues.length; i++) {
            if (qValues[i] > maxQ) {
                maxQ = qValues[i];
                actionIdx = i;
            }
        }
    }

    return {
        actionIdx,
        actionId: DEFENDER_ACTION_IDS[actionIdx],
        isExploration
    };
}

/**
 * Store experience and optionally train
 * @param {Object} agent - DQN agent
 * @param {Object} state - current state
 * @param {number} actionIdx - action taken
 * @param {number} reward - reward received
 * @param {Object} nextState - next state
 * @param {boolean} done - episode ended?
 */
export function updateDQNAgent(agent, state, actionIdx, reward, nextState, done = false) {
    const stateVec = stateToVector(state);
    const nextStateVec = stateToVector(nextState);

    // Store in replay buffer
    agent.replayBuffer.push(stateVec, actionIdx, reward, nextStateVec, done);
    agent.stepCount++;
    agent.totalReward += reward;

    // Train from replay buffer once we have enough samples
    if (agent.replayBuffer.size >= agent.batchSize) {
        const loss = trainDQNBatch(agent);
        agent.trainingLoss.push(loss);
    }

    // Periodically sync target network
    if (agent.stepCount % agent.targetSyncInterval === 0) {
        syncTargetNetwork(agent);
    }
}

/**
 * Train on a mini-batch from replay buffer
 * @param {Object} agent
 * @returns {number} average loss
 */
export function trainDQNBatch(agent) {
    const batch = agent.replayBuffer.sample(agent.batchSize);
    let totalLoss = 0;

    for (const exp of batch) {
        // Compute target Q-value using target network
        const targetQValues = agent.network.forward(exp.state).slice();

        let maxNextQ = 0;
        if (!exp.done) {
            const nextQ = agent.targetNetwork.forward(exp.nextState);
            maxNextQ = Math.max(...nextQ);
        }

        // Bellman target
        targetQValues[exp.action] = exp.reward + agent.gamma * maxNextQ;

        // Forward through policy network (already done above, but need fresh)
        agent.network.forward(exp.state);
        const loss = agent.network.backward(targetQValues, exp.action);
        totalLoss += loss;
    }

    return totalLoss / batch.length;
}

/**
 * Sync target network with policy network
 */
export function syncTargetNetwork(agent) {
    agent.targetNetwork.copyFrom(agent.network);
}

/**
 * Decay epsilon after each episode
 */
export function decayDQNEpsilon(agent) {
    agent.currentEpsilon = Math.max(
        agent.epsilonMin,
        agent.currentEpsilon * agent.epsilonDecay
    );
}

/**
 * Record episode reward
 */
export function recordDQNEpisodeReward(agent, reward) {
    agent.episodeCount++;
    agent.rewardHistory.push(reward);
}

/**
 * Get agent stats for UI
 */
export function getDQNAgentStats(agent) {
    const recent = agent.rewardHistory.slice(-20);
    return {
        type: 'dqn',
        episodes: agent.episodeCount,
        currentEpsilon: agent.currentEpsilon,
        qTableStates: agent.replayBuffer.size, // Comparable metric: experience count
        avgReward: agent.rewardHistory.length > 0 
            ? agent.rewardHistory.reduce((s, v) => s + v, 0) / agent.rewardHistory.length 
            : 0,
        recentAvgReward: recent.length > 0 
            ? recent.reduce((s, v) => s + v, 0) / recent.length 
            : 0,
        rewardHistory: agent.rewardHistory,
        avgLoss: agent.trainingLoss.length > 0
            ? agent.trainingLoss.slice(-100).reduce((s, v) => s + v, 0) / Math.min(agent.trainingLoss.length, 100)
            : 0,
        bufferSize: agent.replayBuffer.size,
        totalSteps: agent.stepCount
    };
}

/**
 * Reset a DQN agent
 */
export function resetDQNAgent(agent) {
    const config = {
        epsilon: agent.epsilon,
        epsilonDecay: agent.epsilonDecay,
        epsilonMin: agent.epsilonMin,
        gamma: agent.gamma,
        batchSize: agent.batchSize,
        targetSyncInterval: agent.targetSyncInterval,
        learningRate: agent.network.lr,
        bufferCapacity: agent.replayBuffer.capacity
    };
    const newAgent = createDQNAgent(config);
    Object.assign(agent, newAgent);
}

/**
 * Export DQN network for persistence
 */
export function exportDQNNetwork(agent) {
    return {
        type: 'dqn',
        network: agent.network.toJSON(),
        targetNetwork: agent.targetNetwork.toJSON(),
        episodeCount: agent.episodeCount,
        currentEpsilon: agent.currentEpsilon,
        rewardHistory: agent.rewardHistory,
        stepCount: agent.stepCount
    };
}

/**
 * Import DQN network from saved data
 */
export function importDQNNetwork(agent, data) {
    if (data.network) {
        agent.network = NeuralNetwork.fromJSON(data.network);
    }
    if (data.targetNetwork) {
        agent.targetNetwork = NeuralNetwork.fromJSON(data.targetNetwork);
    }
    if (data.episodeCount != null) agent.episodeCount = data.episodeCount;
    if (data.currentEpsilon != null) agent.currentEpsilon = data.currentEpsilon;
    if (data.rewardHistory) agent.rewardHistory = data.rewardHistory;
    if (data.stepCount != null) agent.stepCount = data.stepCount;
}

/**
 * Train the DQN agent from stored IOC experience tuples (DB format).
 * Converts state keys to vectors, loads into replay buffer, then runs
 * training batches.
 * 
 * @param {Object} agent - DQN agent created by createDQNAgent()
 * @param {Array<Object>} experiences - DB-format: { stateKey/state_key, actionIdx/action_idx, reward, nextStateKey/next_state_key, done }
 * @param {number} epochs - Number of training passes over the batch (default 3)
 * @returns {{ updatesApplied: number, avgLoss: number, bufferSize: number }}
 */
export function trainFromIOCReplay(agent, experiences, epochs = 3) {
    if (!experiences || experiences.length === 0) {
        return { updatesApplied: 0, avgLoss: 0, bufferSize: agent.replayBuffer.size };
    }

    // 1. Load all experiences into replay buffer as state vectors
    for (const exp of experiences) {
        const sKey = exp.stateKey || exp.state_key;
        const nsKey = exp.nextStateKey || exp.next_state_key;
        if (!sKey) continue;

        const stateVec = stateKeyToVector(sKey);
        const nextStateVec = nsKey ? stateKeyToVector(nsKey) : new Array(INPUT_SIZE).fill(0);
        const actionIdx = typeof exp.actionIdx === 'number' ? exp.actionIdx : (exp.action_idx || 0);
        const reward = typeof exp.reward === 'number' ? exp.reward : 0;
        const done = !!(exp.done);

        agent.replayBuffer.push(stateVec, actionIdx, reward, nextStateVec, done);
    }

    // 2. Run training epochs
    let totalLoss = 0;
    let batchesRun = 0;

    if (agent.replayBuffer.size < agent.batchSize) {
        return { updatesApplied: 0, avgLoss: 0, bufferSize: agent.replayBuffer.size };
    }

    const batchesPerEpoch = Math.max(1, Math.floor(agent.replayBuffer.size / agent.batchSize));

    for (let epoch = 0; epoch < epochs; epoch++) {
        let epochLoss = 0;
        for (let b = 0; b < batchesPerEpoch; b++) {
            const loss = trainDQNBatch(agent);
            epochLoss += loss;
            batchesRun++;

            // Periodic target sync
            if (batchesRun % agent.targetSyncInterval === 0) {
                syncTargetNetwork(agent);
            }
        }

        totalLoss += epochLoss;
        const epochAvgReward = experiences.reduce((s, e) => s + (e.reward || 0), 0) / experiences.length;
        recordDQNEpisodeReward(agent, epochAvgReward);
        decayDQNEpsilon(agent);
    }

    return {
        updatesApplied: batchesRun * agent.batchSize,
        avgLoss: batchesRun > 0 ? Math.round((totalLoss / batchesRun) * 10000) / 10000 : 0,
        bufferSize: agent.replayBuffer.size
    };
}

// Export classes for testing
export { NeuralNetwork, ReplayBuffer };
