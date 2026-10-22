/**
 * POMDP (Partially Observable Markov Decision Process) Formalization
 * 
 * Formalizes the adversarial interaction as a POMDP to provide an exact mathematical model
 * and a computationally rigorous baseline (e.g., 1-step lookahead or Q-MDP value approximation)
 * to compare against the Reinforcement Learning algorithms.
 * 
 * Formal definition:
 * - S: State space (Hidden attacker type × Current tactic phase)
 * - A: Action space (Defender actions)
 * - O: Observation space (Detected techniques or 'null')
 * - T: Transition Model P(s' | s, a)
 * - Z: Observation Model P(o | s', a)
 * - R: Reward function R(s, a)
 */

import { TACTIC_PHASES, TECHNIQUES_BY_TACTIC } from '../data/mitre-catalog.js';
import { ATTACKER_TYPES, selectAttackerTechnique } from '../data/attacker-profiles.js';
import { DEFENDER_ACTION_IDS, getActionEffectiveness } from '../data/defender-actions.js';
import { computeDefenderUtility } from './game-engine.js';

// ═══════════════════════════════════════════════════════════════════════════
//  POMDP EXPLICIT MODELS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Computes Transition Probability T(s' | s, a)
 * State transition is primarily advancing the kill chain.
 * If the defender prevents the attack, state remains the same or terminates.
 * 
 * @param {string} attackerType - S(hidden)
 * @param {number} tacticPhase - S(observable phase)
 * @param {string} actionId - A(defender action)
 * @returns {Array<{nextPhase: number, prob: number, done: boolean}>}
 */
export function getTransitionProbabilities(attackerType, tacticPhase, actionId) {
    if (tacticPhase >= TACTIC_PHASES.length - 1) {
        return [{ nextPhase: tacticPhase, prob: 1.0, done: true }];
    }

    const currentTacticId = TACTIC_PHASES[tacticPhase];
    const prevProb = getActionEffectiveness(actionId, currentTacticId);
    
    return [
        { nextPhase: tacticPhase, prob: prevProb, done: true },          // Prevented and ended
        { nextPhase: tacticPhase + 1, prob: 1 - prevProb, done: false }   // Advanced
    ];
}

/**
 * Computes Observation Probability Z(o | s', a)
 * The attacker picks a technique based on their profile. Due to noise,
 * the defender might observe something else.
 * 
 * @param {string} attackerType - S(hidden)
 * @param {number} tacticPhase - S'(observable phase)
 * @param {number} detectionCoverage - Base detection rate
 * @returns {Object} map of technique ID to probability
 */
export function getObservationModel(attackerType, tacticPhase, detectionCoverage) {
    const currentTacticId = TACTIC_PHASES[tacticPhase];
    const availableTechniques = TECHNIQUES_BY_TACTIC[currentTacticId] || [];
    
    if (availableTechniques.length === 0) {
        return { 'none': 1.0 };
    }

    // Determine the true technique the attacker would pick
    const trueTechnique = selectAttackerTechnique(attackerType, availableTechniques, []);
    if (!trueTechnique) return { 'none': 1.0 };

    const emissionProbs = {};
    const detectionProb = detectionCoverage * (1 - trueTechnique.detectionDifficulty);

    // Probability of observing nothing (false negative + true negative)
    emissionProbs['none'] = 1 - detectionProb;

    // Probability of observing *something*
    if (detectionProb > 0) {
        // True positive (85% of detection events are accurate)
        const truePos = detectionProb * 0.85;
        emissionProbs[trueTechnique.id] = (emissionProbs[trueTechnique.id] || 0) + truePos;

        // Noise (15% spread among alternative techniques in phase)
        const alternatives = availableTechniques.filter(t => t.id !== trueTechnique.id);
        if (alternatives.length > 0) {
            const noiseProb = (detectionProb * 0.15) / alternatives.length;
            alternatives.forEach(alt => {
                emissionProbs[alt.id] = (emissionProbs[alt.id] || 0) + noiseProb;
            });
        } else {
            // Not enough alternatives, dump noise back to true technique
            emissionProbs[trueTechnique.id] += (detectionProb * 0.15);
        }
    }

    return emissionProbs;
}

/**
 * Computes the Expected Reward R(s, a)
 * Weighs the game-theoretic payoff by observation probability
 * 
 * @param {string} attackerType 
 * @param {number} tacticPhase 
 * @param {string} actionId
 * @param {number} detectionCoverage
 * @returns {number} expected utility
 */
export function getExpectedReward(attackerType, tacticPhase, actionId, detectionCoverage) {
    const obModel = getObservationModel(attackerType, tacticPhase, detectionCoverage);
    const currentTacticId = TACTIC_PHASES[tacticPhase];
    const availableTechniques = TECHNIQUES_BY_TACTIC[currentTacticId] || [];
    
    let expectedUtil = 0;
    
    for (const [techId, prob] of Object.entries(obModel)) {
        if (techId === 'none') {
            expectedUtil += prob * (-3); // Miss penalty approximation
            continue;
        }
        
        const technique = availableTechniques.find(t => t.id === techId);
        if (technique) {
            const rawUtil = computeDefenderUtility(actionId, technique, detectionCoverage);
            expectedUtil += prob * rawUtil;
        }
    }
    
    return expectedUtil;
}

// ═══════════════════════════════════════════════════════════════════════════
//  POMDP SOLVER BASELINE (1-Step Lookahead Q-MDP)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Heuristic Baseline Policy resolving partial observability via 1-step lookahead
 * Approximates Q(b, a) = ∑_s b(s) R(s, a) + γ ∑_o P(o|b,a) V(b_a^o)
 * Simplification (Q-MDP): Assumes full observability after one step.
 * 
 * @param {Object} belief - probability distribution over attacker types
 * @param {number} tacticPhase - current observable state
 * @param {number} detectionCoverage 
 * @returns {{bestAction: string, qValues: Object}}
 */
export function solveQMDPOneStep(belief, tacticPhase, detectionCoverage) {
    const qValues = {};
    let bestAction = DEFENDER_ACTION_IDS[0];
    let maxQ = -Infinity;

    for (const actionId of DEFENDER_ACTION_IDS) {
        let expectedActionValue = 0;

        // Iterate over hidden states and weight by belief
        for (const type of ATTACKER_TYPES) {
            const probType = belief[type] || 0;
            if (probType <= 0.01) continue;

            const immediateReward = getExpectedReward(type, tacticPhase, actionId, detectionCoverage);
            
            // Expected future value (Q-MDP approximation assuming full observability next step)
            // Future value depends on transition
            const transitions = getTransitionProbabilities(type, tacticPhase, actionId);
            let futureValue = 0;
            
            for (const trans of transitions) {
                if (trans.done) continue; // 0 future value if ended
                // Approximated "best" response if we perfectly knew the type
                // (Optimistic Q-MDP bounded heuristic)
                futureValue += trans.prob * 1.5; // Rough heuristic constant for future
            }

            expectedActionValue += probType * (immediateReward + 0.95 * futureValue);
        }

        qValues[actionId] = expectedActionValue;
        if (expectedActionValue > maxQ) {
            maxQ = expectedActionValue;
            bestAction = actionId;
        }
    }

    return { bestAction, qValues };
}
