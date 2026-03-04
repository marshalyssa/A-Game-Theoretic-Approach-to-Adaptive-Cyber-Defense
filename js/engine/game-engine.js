/**
 * Game-Theoretic Engine — Payoff Matrices, Mixed Strategies, Nash Equilibrium
 * 
 * Models the attacker-defender interaction as a two-player zero-sum-ish game.
 * Computes payoff matrices and finds optimal mixed strategies.
 * 
 * Utility Functions:
 *   U_defender = detection_benefit × P(detect) - cost - disruption_penalty - FP_penalty + prevention_bonus
 *   U_attacker = objective_value × P(success) - execution_cost - risk_penalty + stealth_bonus
 */

import { TECHNIQUE_BY_ID, TACTIC_BY_ID } from '../data/mitre-catalog.js';
import { DEFENDER_ACTIONS, DEFENDER_ACTION_IDS, getActionEffectiveness } from '../data/defender-actions.js';

// ─── Configuration Constants ───────────────────────────────────────────────
const WEIGHTS = {
    detectionBenefit: 10,      // Reward for detecting an attack
    preventionBonus: 15,       // Reward for preventing an attack
    costPenalty: 8,            // Penalty for action cost
    disruptionPenalty: 12,     // Penalty for operational disruption
    falsePosBonus: -6,         // Penalty for false positives
    attackObjectiveValue: 20,  // Value of attack success to attacker
    riskPenalty: 10,           // Penalty to attacker for being detected
    stealthBonus: 5,           // Bonus for stealthy attack
};

/**
 * Compute defender utility for a specific action against a specific technique
 * 
 * U_defender = W1 × P(detect) + W2 × P(prevent) - W3 × cost - W4 × disruption - W5 × P(FP)
 */
export function computeDefenderUtility(actionId, technique, detectionCoverage = 0.5) {
    const action = DEFENDER_ACTIONS[actionId];
    if (!action || !technique) return 0;

    const tacticId = technique.tacticId;
    const effectiveness = getActionEffectiveness(actionId, tacticId);

    // P(detect) = base detection coverage + action's detection bonus, capped at 1
    const pDetect = Math.min(1, detectionCoverage + action.detectionBonus) * (1 - technique.detectionDifficulty);

    // P(prevent) = action effectiveness against this tactic
    const pPrevent = effectiveness;

    // Compute utility
    const utility =
        WEIGHTS.detectionBenefit * pDetect +
        WEIGHTS.preventionBonus * pPrevent -
        WEIGHTS.costPenalty * action.cost -
        WEIGHTS.disruptionPenalty * action.disruption +
        WEIGHTS.falsePosBonus * action.falsePositiveRate;

    return utility;
}

/**
 * Compute attacker utility for a specific technique against a specific defender action
 * 
 * U_attacker = W1 × P(success) - W2 × exec_cost - W3 × P(detected) + W4 × stealth
 */
export function computeAttackerUtility(technique, actionId, detectionCoverage = 0.5) {
    const action = DEFENDER_ACTIONS[actionId];
    if (!action || !technique) return 0;

    const tacticId = technique.tacticId;
    const effectiveness = getActionEffectiveness(actionId, tacticId);

    // P(success) = 1 - prevention probability
    const pSuccess = 1 - effectiveness;

    // P(detected) = detection coverage adjusted by technique stealth
    const pDetected = Math.min(1, detectionCoverage + action.detectionBonus) * (1 - technique.detectionDifficulty);

    // Compute utility
    const utility =
        WEIGHTS.attackObjectiveValue * pSuccess -
        WEIGHTS.riskPenalty * pDetected -
        technique.executionCost * 5 +
        WEIGHTS.stealthBonus * technique.stealthRating;

    return utility;
}

/**
 * Build the full payoff matrix for a given set of techniques and defender actions
 * Returns { defenderMatrix, attackerMatrix, techniqueIds, actionIds }
 * 
 * defenderMatrix[i][j] = U_defender(action_j, technique_i)
 * attackerMatrix[i][j] = U_attacker(technique_i, action_j)
 */
export function computePayoffMatrix(techniqueIds, actionIds = null, detectionCoverage = 0.5) {
    const actions = actionIds || DEFENDER_ACTION_IDS;
    const defenderMatrix = [];
    const attackerMatrix = [];

    for (const techId of techniqueIds) {
        const technique = TECHNIQUE_BY_ID[techId];
        const defRow = [];
        const atkRow = [];

        for (const actId of actions) {
            defRow.push(computeDefenderUtility(actId, technique, detectionCoverage));
            atkRow.push(computeAttackerUtility(technique, actId, detectionCoverage));
        }

        defenderMatrix.push(defRow);
        attackerMatrix.push(atkRow);
    }

    return {
        defenderMatrix,
        attackerMatrix,
        techniqueIds,
        actionIds: actions,
        rows: techniqueIds.length,
        cols: actions.length
    };
}

/**
 * Find the best pure strategy response for the defender
 * Given a probability distribution over attacker techniques, find the action
 * that maximizes expected defender utility
 * 
 * @param {number[]} attackerDist - probability over techniques (rows)
 * @param {number[][]} defenderMatrix - payoff matrix
 * @param {string[]} actionIds - action labels
 * @returns {{ actionId: string, expectedUtility: number, allUtilities: Object }}
 */
export function bestDefenderResponse(attackerDist, defenderMatrix, actionIds) {
    const numActions = actionIds.length;
    const expectedUtilities = new Array(numActions).fill(0);

    // For each action, compute expected utility across attacker technique distribution
    for (let j = 0; j < numActions; j++) {
        for (let i = 0; i < attackerDist.length; i++) {
            expectedUtilities[j] += attackerDist[i] * defenderMatrix[i][j];
        }
    }

    // Find the action with maximum expected utility
    let bestIdx = 0;
    let bestEU = expectedUtilities[0];
    for (let j = 1; j < numActions; j++) {
        if (expectedUtilities[j] > bestEU) {
            bestEU = expectedUtilities[j];
            bestIdx = j;
        }
    }

    const allUtilities = {};
    for (let j = 0; j < numActions; j++) {
        allUtilities[actionIds[j]] = Math.round(expectedUtilities[j] * 100) / 100;
    }

    return {
        actionId: actionIds[bestIdx],
        expectedUtility: Math.round(bestEU * 100) / 100,
        allUtilities
    };
}

/**
 * Compute mixed strategy Nash equilibrium for a 2-player game
 * Uses iterative support enumeration for small games
 * Falls back to fictitious play for larger games
 * 
 * @param {number[][]} defenderMatrix - defender payoffs (techniques × actions)
 * @param {number[][]} attackerMatrix - attacker payoffs (techniques × actions)
 * @returns {{ defenderStrategy: number[], attackerStrategy: number[], defenderValue: number, attackerValue: number }}
 */
export function solveMixedStrategy(defenderMatrix, attackerMatrix) {
    const numTech = defenderMatrix.length;
    const numAct = defenderMatrix[0].length;

    // Use fictitious play for general games
    return fictitiousPlay(defenderMatrix, attackerMatrix, numTech, numAct, 1000);
}

/**
 * Fictitious Play — iterative algorithm to approximate Nash equilibrium
 * Each player best-responds to the empirical frequency of the opponent's past actions
 */
function fictitiousPlay(defenderMatrix, attackerMatrix, numTech, numAct, iterations) {
    // Cumulative counts
    const attackerCounts = new Array(numTech).fill(1);  // Start with uniform
    const defenderCounts = new Array(numAct).fill(1);

    for (let iter = 0; iter < iterations; iter++) {
        // Attacker best responds to defender's empirical strategy
        const defTotal = defenderCounts.reduce((s, c) => s + c, 0);
        const defFreq = defenderCounts.map(c => c / defTotal);

        let bestAtkIdx = 0;
        let bestAtkVal = -Infinity;
        for (let i = 0; i < numTech; i++) {
            let ev = 0;
            for (let j = 0; j < numAct; j++) {
                ev += defFreq[j] * attackerMatrix[i][j];
            }
            if (ev > bestAtkVal) {
                bestAtkVal = ev;
                bestAtkIdx = i;
            }
        }
        attackerCounts[bestAtkIdx]++;

        // Defender best responds to attacker's empirical strategy
        const atkTotal = attackerCounts.reduce((s, c) => s + c, 0);
        const atkFreq = attackerCounts.map(c => c / atkTotal);

        let bestDefIdx = 0;
        let bestDefVal = -Infinity;
        for (let j = 0; j < numAct; j++) {
            let ev = 0;
            for (let i = 0; i < numTech; i++) {
                ev += atkFreq[i] * defenderMatrix[i][j];
            }
            if (ev > bestDefVal) {
                bestDefVal = ev;
                bestDefIdx = j;
            }
        }
        defenderCounts[bestDefIdx]++;
    }

    // Convert counts to strategies
    const atkTotal = attackerCounts.reduce((s, c) => s + c, 0);
    const defTotal = defenderCounts.reduce((s, c) => s + c, 0);

    const attackerStrategy = attackerCounts.map(c => Math.round((c / atkTotal) * 1000) / 1000);
    const defenderStrategy = defenderCounts.map(c => Math.round((c / defTotal) * 1000) / 1000);

    // Compute expected values
    let defValue = 0, atkValue = 0;
    for (let i = 0; i < numTech; i++) {
        for (let j = 0; j < numAct; j++) {
            defValue += attackerStrategy[i] * defenderStrategy[j] * defenderMatrix[i][j];
            atkValue += attackerStrategy[i] * defenderStrategy[j] * attackerMatrix[i][j];
        }
    }

    return {
        defenderStrategy,
        attackerStrategy,
        defenderValue: Math.round(defValue * 100) / 100,
        attackerValue: Math.round(atkValue * 100) / 100
    };
}

/**
 * Compute expected utility of a strategy against a payoff matrix
 * @param {number[]} ownStrategy - probability distribution over own actions
 * @param {number[]} opponentStrategy - probability distribution over opponent actions
 * @param {number[][]} payoffMatrix - own payoff matrix
 * @returns {number} expected utility
 */
export function expectedUtility(ownStrategy, opponentStrategy, payoffMatrix) {
    let eu = 0;
    for (let i = 0; i < ownStrategy.length; i++) {
        for (let j = 0; j < opponentStrategy.length; j++) {
            eu += ownStrategy[i] * opponentStrategy[j] * payoffMatrix[i][j];
        }
    }
    return Math.round(eu * 100) / 100;
}

/**
 * Get a ranked list of defender actions by expected utility against current threat
 * @param {Object} predictedTechDist - { techniqueId: probability }
 * @param {number} detectionCoverage - current detection coverage [0,1]
 * @returns {Array<{actionId: string, name: string, expectedUtility: number, cost: number, disruption: number}>}
 */
export function rankDefenderActions(predictedTechDist, detectionCoverage = 0.5) {
    const techEntries = Object.entries(predictedTechDist)
        .filter(([, p]) => p > 0.01)
        .sort((a, b) => b[1] - a[1]);

    // Build small payoff matrix for top techniques
    const topTechIds = techEntries.slice(0, 10).map(([id]) => id);
    const topTechProbs = techEntries.slice(0, 10).map(([, p]) => p);

    // Normalize probabilities
    const probSum = topTechProbs.reduce((s, p) => s + p, 0);
    const normProbs = topTechProbs.map(p => p / probSum);

    const payoff = computePayoffMatrix(topTechIds, DEFENDER_ACTION_IDS, detectionCoverage);
    const best = bestDefenderResponse(normProbs, payoff.defenderMatrix, payoff.actionIds);

    return DEFENDER_ACTION_IDS.map(actionId => ({
        actionId,
        name: DEFENDER_ACTIONS[actionId].name,
        expectedUtility: best.allUtilities[actionId] || 0,
        cost: DEFENDER_ACTIONS[actionId].cost,
        disruption: DEFENDER_ACTIONS[actionId].disruption
    })).sort((a, b) => b.expectedUtility - a.expectedUtility);
}
