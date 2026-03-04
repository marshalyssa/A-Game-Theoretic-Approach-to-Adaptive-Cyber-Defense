/**
 * Bayesian Belief Engine — Attacker Type Inference
 * 
 * Maintains a probability distribution over attacker types and updates
 * it using Bayes' theorem as new technique observations arrive.
 * 
 * Belief State: B(t) = [P(script_kiddie), P(organized_crime), P(apt_state), P(insider_threat)]
 * Update Rule:  P(type_i | obs) ∝ P(obs | type_i) × P(type_i)
 */

import { ATTACKER_TYPES, getTechniqueLikelihood } from '../data/attacker-profiles.js';
import { getTransitionDistribution, TECHNIQUE_BY_ID, TACTIC_BY_ID } from '../data/mitre-catalog.js';

/**
 * Create a new belief state with optional prior
 * @param {Object} prior - optional { type: probability } mapping
 * @returns {Object} belief state
 */
export function createBeliefState(prior = null) {
    const belief = {};
    if (prior) {
        let sum = 0;
        for (const type of ATTACKER_TYPES) {
            belief[type] = prior[type] || 0;
            sum += belief[type];
        }
        // Normalize
        for (const type of ATTACKER_TYPES) {
            belief[type] = sum > 0 ? belief[type] / sum : 1 / ATTACKER_TYPES.length;
        }
    } else {
        // Uniform prior
        const uniform = 1 / ATTACKER_TYPES.length;
        for (const type of ATTACKER_TYPES) {
            belief[type] = uniform;
        }
    }
    return belief;
}

/**
 * Update belief state using Bayes' theorem given an observed technique
 * P(type | observation) ∝ P(observation | type) × P(type)
 * 
 * @param {Object} belief - current belief state
 * @param {string} observedTechniqueId - MITRE technique ID observed
 * @returns {Object} updated belief state
 */
export function updateBelief(belief, observedTechniqueId) {
    const posterior = {};
    let totalPosterior = 0;

    for (const type of ATTACKER_TYPES) {
        // Likelihood: P(technique | attacker_type)
        const likelihood = getTechniqueLikelihood(type, observedTechniqueId);
        // Prior: current belief
        const prior = belief[type];
        // Unnormalized posterior
        posterior[type] = likelihood * prior;
        totalPosterior += posterior[type];
    }

    // Normalize to get proper probability distribution
    if (totalPosterior > 0) {
        for (const type of ATTACKER_TYPES) {
            posterior[type] /= totalPosterior;
        }
    } else {
        // Fallback to uniform if all likelihoods are zero
        const uniform = 1 / ATTACKER_TYPES.length;
        for (const type of ATTACKER_TYPES) {
            posterior[type] = uniform;
        }
    }

    return posterior;
}

/**
 * Batch update belief with multiple observations
 * @param {Object} belief - current belief state
 * @param {string[]} observedTechniqueIds - array of technique IDs
 * @returns {Object} updated belief state
 */
export function updateBeliefBatch(belief, observedTechniqueIds) {
    let current = { ...belief };
    for (const techId of observedTechniqueIds) {
        current = updateBelief(current, techId);
    }
    return current;
}

/**
 * Apply temporal decay — beliefs drift toward uniform over time
 * Captures staleness of observations
 * 
 * @param {Object} belief - current belief state
 * @param {number} decayRate - [0,1] per timestep decay (0 = no decay, 1 = instant uniform)
 * @returns {Object} decayed belief state
 */
export function decayBelief(belief, decayRate = 0.05) {
    const uniform = 1 / ATTACKER_TYPES.length;
    const decayed = {};
    for (const type of ATTACKER_TYPES) {
        decayed[type] = belief[type] * (1 - decayRate) + uniform * decayRate;
    }
    return decayed;
}

/**
 * Calculate Shannon entropy of belief distribution
 * Higher entropy = more uncertainty about attacker type
 * Max entropy = log2(4) ≈ 2.0 (uniform over 4 types)
 * 
 * @param {Object} belief - belief state
 * @returns {number} entropy in bits
 */
export function getBeliefEntropy(belief) {
    let entropy = 0;
    for (const type of ATTACKER_TYPES) {
        const p = belief[type];
        if (p > 0) {
            entropy -= p * Math.log2(p);
        }
    }
    return entropy;
}

/**
 * Get the maximum entropy (uniform distribution)
 * @returns {number} max possible entropy
 */
export function getMaxEntropy() {
    return Math.log2(ATTACKER_TYPES.length);
}

/**
 * Get the most probable attacker type from belief state
 * @param {Object} belief - belief state
 * @returns {{ type: string, probability: number }}
 */
export function getMostProbableType(belief) {
    let maxType = ATTACKER_TYPES[0];
    let maxProb = 0;
    for (const type of ATTACKER_TYPES) {
        if (belief[type] > maxProb) {
            maxProb = belief[type];
            maxType = type;
        }
    }
    return { type: maxType, probability: maxProb };
}

/**
 * Predict the next technique probability distribution
 * Combines across attacker types weighted by belief, using transition matrix
 * 
 * P(next_tech) = Σ_type [ P(type) × Σ_tech [ P(type_uses_tech) × P(next_tech | tech) ] ]
 * 
 * Simplified: given the last observed technique, predict next weighted by type beliefs
 * 
 * @param {Object} belief - current belief state
 * @param {string} lastTechniqueId - last observed technique
 * @returns {Object} { techniqueId: probability } distribution over next techniques
 */
export function predictNextTechnique(belief, lastTechniqueId) {
    // Get base transition distribution from the last technique
    const transitionDist = getTransitionDistribution(lastTechniqueId);

    // Weight transitions by attacker type likelihood modifiers
    const prediction = {};
    let total = 0;

    for (const [techId, baseProb] of Object.entries(transitionDist)) {
        let weightedProb = 0;
        for (const type of ATTACKER_TYPES) {
            const typeWeight = belief[type];
            const typeLikelihood = getTechniqueLikelihood(type, techId);
            weightedProb += typeWeight * typeLikelihood * baseProb;
        }
        prediction[techId] = weightedProb;
        total += weightedProb;
    }

    // Normalize
    if (total > 0) {
        for (const techId in prediction) {
            prediction[techId] /= total;
        }
    }

    return prediction;
}

/**
 * Get top-N predicted next techniques sorted by probability
 * @param {Object} belief - current belief state
 * @param {string} lastTechniqueId - last observed technique
 * @param {number} n - number of top predictions
 * @returns {Array<{id: string, name: string, probability: number, tacticId: string}>}
 */
export function getTopPredictions(belief, lastTechniqueId, n = 5) {
    const prediction = predictNextTechnique(belief, lastTechniqueId);

    return Object.entries(prediction)
        .map(([id, probability]) => {
            const tech = TECHNIQUE_BY_ID[id];
            return {
                id,
                name: tech ? tech.name : id,
                probability,
                tacticId: tech ? tech.tacticId : 'unknown',
                tacticName: tech ? (TACTIC_BY_ID[tech.tacticId]?.name || 'Unknown') : 'Unknown'
            };
        })
        .sort((a, b) => b.probability - a.probability)
        .slice(0, n);
}
