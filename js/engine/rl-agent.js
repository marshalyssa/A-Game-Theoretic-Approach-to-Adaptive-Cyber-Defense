/**
 * Reinforcement Learning Agent — Q-Learning Defender
 * 
 * Learns optimal defender policy through repeated episodes of attacker-defender interaction.
 * Uses ε-greedy action selection with annealing for exploration vs exploitation.
 * 
 * State: (tactic_phase, belief_bucket, alert_severity, asset_criticality, last_action_idx)
 * Action: defender action index
 * Reward: defender utility from game engine + bonuses/penalties
 */

import { DEFENDER_ACTION_IDS } from '../data/defender-actions.js';
import { ATTACKER_TYPES } from '../data/attacker-profiles.js';

// ─── State Discretization ──────────────────────────────────────────────────
const BELIEF_BUCKETS = 4;     // Discretize belief entropy into 4 buckets
const SEVERITY_LEVELS = 3;    // LOW, MEDIUM, HIGH
const CRITICALITY_LEVELS = 3; // LOW, MEDIUM, HIGH
const TACTIC_PHASES = 14;     // 14 ATT&CK tactic stages

/**
 * Discretize a continuous belief state into a bucket index
 * Based on which attacker type has the highest probability
 */
function discretizeBelief(belief) {
    let maxType = 0;
    let maxProb = 0;
    for (let i = 0; i < ATTACKER_TYPES.length; i++) {
        const p = belief[ATTACKER_TYPES[i]] || 0;
        if (p > maxProb) {
            maxProb = p;
            maxType = i;
        }
    }
    return maxType; // 0-3 corresponding to 4 attacker types
}

/**
 * Convert state components into a string key for Q-table lookup
 */
function stateToKey(tacticPhase, beliefBucket, severity, criticality, lastActionIdx) {
    return `${tacticPhase}_${beliefBucket}_${severity}_${criticality}_${lastActionIdx}`;
}

/**
 * Create a new RL agent with configuration
 * @param {Object} config - { alpha, gamma, epsilon, epsilonDecay, epsilonMin }
 * @returns {Object} agent with Q-table and methods
 */
export function createAgent(config = {}) {
    const alpha = config.alpha || 0.1;             // Learning rate
    const gamma = config.gamma || 0.95;            // Discount factor
    const epsilon = config.epsilon || 0.3;         // Initial exploration rate
    const epsilonDecay = config.epsilonDecay || 0.995; // Per-episode decay
    const epsilonMin = config.epsilonMin || 0.01;  // Minimum exploration

    return {
        qTable: {},           // state_key → action_index → Q-value
        alpha,
        gamma,
        epsilon,
        epsilonDecay,
        epsilonMin,
        currentEpsilon: epsilon,
        numActions: DEFENDER_ACTION_IDS.length,
        episodeCount: 0,
        totalReward: 0,
        rewardHistory: [],    // Per-episode cumulative rewards
        stepCount: 0
    };
}

/**
 * Get Q-values for a state, initializing if needed
 */
function getQValues(agent, stateKey) {
    if (!agent.qTable[stateKey]) {
        agent.qTable[stateKey] = new Array(agent.numActions).fill(0);
    }
    return agent.qTable[stateKey];
}

/**
 * Select an action using ε-greedy policy
 * @param {Object} agent - RL agent
 * @param {Object} state - { tacticPhase, belief, severity, criticality, lastActionIdx }
 * @returns {{ actionIdx: number, actionId: string, isExploration: boolean }}
 */
export function selectAction(agent, state) {
    const beliefBucket = discretizeBelief(state.belief);
    const stateKey = stateToKey(
        state.tacticPhase,
        beliefBucket,
        state.severity || 1,
        state.criticality || 1,
        state.lastActionIdx || 0
    );

    const qValues = getQValues(agent, stateKey);
    let actionIdx;
    let isExploration = false;

    if (Math.random() < agent.currentEpsilon) {
        // Explore: random action
        actionIdx = Math.floor(Math.random() * agent.numActions);
        isExploration = true;
    } else {
        // Exploit: best known action
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
 * Update Q-value using Q-learning update rule:
 * Q(s,a) ← Q(s,a) + α[r + γ max_a' Q(s',a') - Q(s,a)]
 * 
 * @param {Object} agent - RL agent
 * @param {Object} state - current state
 * @param {number} actionIdx - action taken
 * @param {number} reward - reward received
 * @param {Object} nextState - next state after transition
 * @param {boolean} done - whether episode ended
 */
export function updateAgent(agent, state, actionIdx, reward, nextState, done = false) {
    const beliefBucket = discretizeBelief(state.belief);
    const stateKey = stateToKey(
        state.tacticPhase,
        beliefBucket,
        state.severity || 1,
        state.criticality || 1,
        state.lastActionIdx || 0
    );

    const qValues = getQValues(agent, stateKey);
    const currentQ = qValues[actionIdx];

    let maxNextQ = 0;
    if (!done) {
        const nextBeliefBucket = discretizeBelief(nextState.belief);
        const nextStateKey = stateToKey(
            nextState.tacticPhase,
            nextBeliefBucket,
            nextState.severity || 1,
            nextState.criticality || 1,
            nextState.lastActionIdx || 0
        );
        const nextQValues = getQValues(agent, nextStateKey);
        maxNextQ = Math.max(...nextQValues);
    }

    // Q-learning update rule
    const tdTarget = reward + agent.gamma * maxNextQ;
    const tdError = tdTarget - currentQ;
    qValues[actionIdx] = currentQ + agent.alpha * tdError;

    agent.stepCount++;
    agent.totalReward += reward;
}

/**
 * Decay exploration rate at the end of an episode
 */
export function decayEpsilon(agent) {
    agent.currentEpsilon = Math.max(
        agent.epsilonMin,
        agent.currentEpsilon * agent.epsilonDecay
    );
    agent.episodeCount++;
}

/**
 * Record episode reward for tracking
 */
export function recordEpisodeReward(agent, episodeReward) {
    agent.rewardHistory.push(episodeReward);
}

/**
 * Get the learned policy for a state (best action without exploration)
 */
export function getPolicy(agent, state) {
    const beliefBucket = discretizeBelief(state.belief);
    const stateKey = stateToKey(
        state.tacticPhase,
        beliefBucket,
        state.severity || 1,
        state.criticality || 1,
        state.lastActionIdx || 0
    );

    const qValues = getQValues(agent, stateKey);
    let bestIdx = 0;
    let maxQ = qValues[0];
    for (let i = 1; i < qValues.length; i++) {
        if (qValues[i] > maxQ) {
            maxQ = qValues[i];
            bestIdx = i;
        }
    }

    return {
        actionIdx: bestIdx,
        actionId: DEFENDER_ACTION_IDS[bestIdx],
        qValue: Math.round(maxQ * 100) / 100
    };
}

/**
 * Get agent statistics for UI display
 */
export function getAgentStats(agent) {
    const qTableSize = Object.keys(agent.qTable).length;
    const avgReward = agent.rewardHistory.length > 0
        ? agent.rewardHistory.reduce((s, r) => s + r, 0) / agent.rewardHistory.length
        : 0;

    // Moving average of last 10 episodes
    const last10 = agent.rewardHistory.slice(-10);
    const recentAvg = last10.length > 0
        ? last10.reduce((s, r) => s + r, 0) / last10.length
        : 0;

    return {
        episodes: agent.episodeCount,
        totalSteps: agent.stepCount,
        currentEpsilon: Math.round(agent.currentEpsilon * 1000) / 1000,
        qTableStates: qTableSize,
        avgReward: Math.round(avgReward * 100) / 100,
        recentAvgReward: Math.round(recentAvg * 100) / 100,
        rewardHistory: agent.rewardHistory
    };
}

/**
 * Reset agent for fresh training (preserves configuration)
 */
export function resetAgent(agent) {
    agent.qTable = {};
    agent.currentEpsilon = agent.epsilon;
    agent.episodeCount = 0;
    agent.totalReward = 0;
    agent.rewardHistory = [];
    agent.stepCount = 0;
}
