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
 * If wasDetected is false, it uses "Negative Evidence":
 * P(type | no_obs) ∝ P(no_obs | type) × P(type)
 * 
 * @param {Object} belief - current belief state
 * @param {string|null} observedTechniqueId - MITRE technique ID observed (if any)
 * @param {boolean} wasDetected - whether a detection occurred
 * @returns {Object} updated belief state
 */
export function updateBelief(belief, observedTechniqueId, wasDetected = true) {
    const posterior = {};
    let totalPosterior = 0;

    for (const type of ATTACKER_TYPES) {
        let likelihood = 1.0;

        if (wasDetected && observedTechniqueId) {
            // Positive likelihood: P(obs | type)
            likelihood = getTechniqueLikelihood(type, observedTechniqueId);
        } else if (!wasDetected) {
            // Negative likelihood: P(no_obs | type)
            // Stealthier types (like apt_state) have higher P(no_obs)
            likelihood = getNegativeLikelihood(type);
        }

        const prior = belief[type];
        posterior[type] = likelihood * prior;
        totalPosterior += posterior[type];
    }

    // Normalize
    if (totalPosterior > 0) {
        for (const type of ATTACKER_TYPES) {
            posterior[type] /= totalPosterior;
        }
    } else {
        const uniform = 1 / ATTACKER_TYPES.length;
        for (const type of ATTACKER_TYPES) {
            posterior[type] = uniform;
        }
    }

    return posterior;
}

/**
 * P(no_obs | type) — Probability of an execution NOT being detected
 * Stealthy types have higher values (APT > Insider > Crime > Kiddie)
 */
function getNegativeLikelihood(type) {
    const profiles = {
        'apt_state': 0.85,       // 85% chance to remain hidden
        'insider_threat': 0.70,   // 70% chance to remain hidden
        'organized_crime': 0.40,  // 40% chance to remain hidden
        'script_kiddie': 0.15     // 15% chance to remain hidden
    };
    return profiles[type] || 0.5;
}

/**
 * Batch update belief with multiple observations
 */
export function updateBeliefBatch(belief, observations) {
    let current = { ...belief };
    for (const obs of observations) {
        if (typeof obs === 'string') {
            // Plain technique ID string
            current = updateBelief(current, obs);
        } else {
            // Observation object { id, detected }
            current = updateBelief(current, obs.id, obs.detected !== false);
        }
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
 * Predict the next technique using a Hidden Intent model (Simplified HMM)
 * 1. Predict the likely next TACTIC (Intent) for each attacker type
 * 2. Predict the likely next TECHNIQUE within those tactics
 * 
 * P(next_tech) = Σ_type [ P(type) × Σ_tactic [ P(tactic | last_tech, type) × P(tech | tactic, type) ] ]
 * 
 * @param {Object} belief - current belief state
 * @param {string} lastTechniqueId - last observed technique
 * @returns {Object} { techniqueId: probability } distribution over next techniques
 */
export function predictNextTechnique(belief, lastTechniqueId) {
    const lastTech = TECHNIQUE_BY_ID[lastTechniqueId];
    if (!lastTech) return {};

    const currentTacticId = lastTech.tacticId;
    const prediction = {};
    let total = 0;

    for (const type of ATTACKER_TYPES) {
        const typeWeight = belief[type];
        if (typeWeight < 0.01) continue; // Skip negligible types

        // 1. Get possible next tactics and their transition probabilities for this type
        const nextTactics = getNextPossibleTactics(currentTacticId, type);

        for (const [nextTacticId, tacticProb] of Object.entries(nextTactics)) {
            // 2. Get likelihood of techniques within that tactic for this type
            const techniques = TECHNIQUES_BY_TACTIC[nextTacticId] || [];
            if (techniques.length === 0) continue;

            const techLikelihoods = {};
            let techTotal = 0;
            for (const tech of techniques) {
                const likelihood = getTechniqueLikelihood(type, tech.id);
                // Factor in base transition from last technique if it exists
                const transitionProb = getTransitionDistribution(lastTechniqueId)[tech.id] || 0.1;
                techLikelihoods[tech.id] = likelihood * transitionProb;
                techTotal += techLikelihoods[tech.id];
            }

            // 3. Accumulate weighted probabilities
            for (const techId in techLikelihoods) {
                const prob = typeWeight * tacticProb * (techLikelihoods[techId] / (techTotal || 1));
                prediction[techId] = (prediction[techId] || 0) + prob;
                total += prob;
            }
        }
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
 * P(next_tactic | current_tactic, type)
 * Models attacker intent flow based on profile progression data
 */
function getNextPossibleTactics(currentTacticId, type) {
    const profile = ATTACKER_PROFILES[type];
    const tacticsOrder = TACTIC_PHASES;
    const currentIdx = tacticsOrder.indexOf(currentTacticId);

    if (currentIdx === -1) return { [tacticsOrder[0]]: 1.0 };

    const result = {};

    // 1. Probability of staying/retrying (persistence)
    const stayProb = profile ? profile.persistence * 0.4 : 0.2;
    result[currentTacticId] = stayProb;

    // 2. Probability of moving to next adjacent tactic
    if (currentIdx + 1 < tacticsOrder.length) {
        const nextTacticId = tacticsOrder[currentIdx + 1];
        const progressProb = profile ? (profile.tacticProgression[nextTacticId] || 0.7) : 0.7;
        result[nextTacticId] = (1 - stayProb) * progressProb;
    }

    // 3. Probability of skipping (stealth/evasion)
    if (currentIdx + 2 < tacticsOrder.length) {
        const skipTacticId = tacticsOrder[currentIdx + 2];
        const skipProb = profile ? (1 - stayProb) * (1 - (profile.tacticProgression[tacticsOrder[currentIdx + 1]] || 0.7)) : 0.1;
        result[skipTacticId] = skipProb;
    }

    // Normalize
    let sum = 0;
    for (const p of Object.values(result)) sum += p;
    for (const t in result) result[t] /= sum;

    return result;
}

import { TACTIC_PHASES, TECHNIQUES_BY_TACTIC } from '../data/mitre-catalog.js';
import { ATTACKER_PROFILES } from '../data/attacker-profiles.js';

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
