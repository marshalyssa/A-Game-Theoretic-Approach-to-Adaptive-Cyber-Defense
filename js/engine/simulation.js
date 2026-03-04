/**
 * Simulation Engine — Sequential Imperfect Information Game
 * 
 * Orchestrates the adversarial interaction:
 * 1. Attacker selects technique based on type, stage, and defender response
 * 2. Detection check: noisy observation of technique
 * 3. Bayesian belief update
 * 4. Game-theoretic & RL-based defender action selection
 * 5. Utility computation and state transition
 * 6. Metrics recording
 */

import { TACTICS, TACTIC_PHASES, TECHNIQUES_BY_TACTIC, TECHNIQUE_BY_ID, getTacticPhase } from '../data/mitre-catalog.js';
import { ATTACKER_PROFILES, ATTACKER_TYPES, selectAttackerTechnique, shouldProgress } from '../data/attacker-profiles.js';
import { DEFENDER_ACTIONS, DEFENDER_ACTION_IDS, getActionEffectiveness } from '../data/defender-actions.js';
import { createBeliefState, updateBelief, decayBelief, getBeliefEntropy, getMostProbableType, predictNextTechnique, getTopPredictions } from './bayesian-engine.js';
import { computeDefenderUtility, computeAttackerUtility, computePayoffMatrix, bestDefenderResponse, solveMixedStrategy, rankDefenderActions } from './game-engine.js';
import { createAgent, selectAction, updateAgent, decayEpsilon, recordEpisodeReward, getAgentStats, resetAgent } from './rl-agent.js';

// ─── Simulation Configuration ──────────────────────────────────────────────
const DEFAULT_CONFIG = {
    attackerType: 'apt_state',        // True attacker type (hidden from defender)
    detectionCoverage: 0.5,           // Base detection probability [0,1]
    assetCriticality: 2,              // 0=LOW, 1=MEDIUM, 2=HIGH
    alertSeverity: 1,                 // 0=LOW, 1=MEDIUM, 2=HIGH
    maxSteps: 20,                     // Max timesteps per episode
    noisyObservation: true,           // Whether detection is probabilistic
    beliefDecayRate: 0.03,            // Belief staleness decay per step
    useRL: true,                      // Whether RL agent participates
    useGameTheory: true,              // Whether game-theoretic analysis runs
    prior: null,                      // Custom prior for belief (null = uniform)
};

/**
 * Create a new simulation configuration
 */
export function createSimConfig(overrides = {}) {
    return { ...DEFAULT_CONFIG, ...overrides };
}

/**
 * Initialize a new simulation state
 */
export function initSimulation(config) {
    const conf = createSimConfig(config);

    return {
        config: conf,
        timestep: 0,
        currentTacticIdx: 0,                       // Index into TACTIC_PHASES
        belief: createBeliefState(conf.prior),      // Bayesian belief over attacker types
        history: [],                                 // Full game trace
        defenderActions: [],                        // Actions taken so far
        attackerTechniques: [],                     // Techniques used so far
        detections: [],                             // Detection outcomes
        cumulativeDefenderUtility: 0,
        cumulativeAttackerUtility: 0,
        attackDetected: false,                      // Whether attack has been detected overall
        attackPrevented: false,                     // Whether attack was prevented
        gameOver: false,
        metrics: null                               // Computed at end
    };
}

/**
 * Execute one timestep of the simulation
 * Returns the step result and updates the state in-place
 */
export function stepSimulation(state, rlAgent = null) {
    if (state.gameOver) return null;

    const config = state.config;
    const t = state.timestep;

    // ── 1. Determine current tactic ──
    const currentTacticId = TACTIC_PHASES[state.currentTacticIdx];
    const currentTactic = TACTICS[state.currentTacticIdx];
    const availableTechniques = TECHNIQUES_BY_TACTIC[currentTacticId] || [];

    if (availableTechniques.length === 0) {
        // Skip empty tactic stages
        state.currentTacticIdx = Math.min(state.currentTacticIdx + 1, TACTIC_PHASES.length - 1);
        if (state.currentTacticIdx >= TACTIC_PHASES.length - 1) {
            state.gameOver = true;
        }
        return stepSimulation(state, rlAgent); // Recurse to next tactic
    }

    // ── 2. Attacker selects technique ──
    const attackerType = config.attackerType;
    const technique = selectAttackerTechnique(attackerType, availableTechniques, state.defenderActions);
    if (!technique) {
        state.gameOver = true;
        return null;
    }

    // ── 3. Detection check ──
    let detected = false;
    let observedTechniqueId = null;
    const detectionProb = config.detectionCoverage * (1 - technique.detectionDifficulty);

    if (config.noisyObservation) {
        detected = Math.random() < detectionProb;
    } else {
        detected = detectionProb > 0.5;
    }

    if (detected) {
        // Observe the technique (possibly with noise)
        if (Math.random() < 0.85) {
            observedTechniqueId = technique.id; // Correct observation
        } else {
            // Noisy: observe a different technique from the same tactic
            const alternatives = availableTechniques.filter(t => t.id !== technique.id);
            observedTechniqueId = alternatives.length > 0
                ? alternatives[Math.floor(Math.random() * alternatives.length)].id
                : technique.id;
        }
        state.attackDetected = true;
    }

    // ── 4. Bayesian belief update ──
    let oldBelief = { ...state.belief };
    if (detected && observedTechniqueId) {
        state.belief = updateBelief(state.belief, observedTechniqueId);
    }
    // Apply temporal decay
    state.belief = decayBelief(state.belief, config.beliefDecayRate);

    // ── 5. Predict next technique ──
    const predictions = detected && observedTechniqueId
        ? getTopPredictions(state.belief, observedTechniqueId, 5)
        : [];

    // ── 6. Game-theoretic analysis ──
    let gameAnalysis = null;
    let rankedActions = null;
    if (config.useGameTheory && detected) {
        const techDist = predictNextTechnique(state.belief, observedTechniqueId || technique.id);
        rankedActions = rankDefenderActions(techDist, config.detectionCoverage);
        gameAnalysis = {
            rankedActions: rankedActions.slice(0, 5),
            bestAction: rankedActions[0]
        };
    }

    // ── 7. Select defender action ──
    let defenderActionId = 'monitor'; // Default
    let isRLAction = false;
    let isExploration = false;
    let rlActionResult = null;

    if (config.useRL && rlAgent) {
        // RL agent selects action
        const rlState = {
            tacticPhase: state.currentTacticIdx,
            belief: state.belief,
            severity: config.alertSeverity,
            criticality: config.assetCriticality,
            lastActionIdx: state.defenderActions.length > 0
                ? DEFENDER_ACTION_IDS.indexOf(state.defenderActions[state.defenderActions.length - 1])
                : 0
        };
        rlActionResult = selectAction(rlAgent, rlState);
        defenderActionId = rlActionResult.actionId;
        isRLAction = true;
        isExploration = rlActionResult.isExploration;
    } else if (gameAnalysis) {
        // Use game-theoretic recommendation
        defenderActionId = gameAnalysis.bestAction.actionId;
    }

    // ── 8. Compute utilities ──
    const defUtil = computeDefenderUtility(defenderActionId, technique, config.detectionCoverage);
    const atkUtil = computeAttackerUtility(technique, defenderActionId, config.detectionCoverage);

    state.cumulativeDefenderUtility += defUtil;
    state.cumulativeAttackerUtility += atkUtil;

    // ── 9. Check if attack was prevented ──
    const preventionProb = getActionEffectiveness(defenderActionId, currentTacticId);
    const attackPrevented = Math.random() < preventionProb;

    // ── 10. Compute RL reward ──
    let reward = defUtil;
    if (detected) reward += 2;           // Bonus for detection
    if (attackPrevented) reward += 5;    // Bonus for prevention
    if (!detected) reward -= 3;          // Penalty for missed detection

    // ── 11. Update RL agent ──
    if (config.useRL && rlAgent && rlActionResult) {
        const nextState = {
            tacticPhase: Math.min(state.currentTacticIdx + 1, TACTIC_PHASES.length - 1),
            belief: state.belief,
            severity: config.alertSeverity,
            criticality: config.assetCriticality,
            lastActionIdx: rlActionResult.actionIdx
        };
        updateAgent(rlAgent, {
            tacticPhase: state.currentTacticIdx,
            belief: oldBelief,
            severity: config.alertSeverity,
            criticality: config.assetCriticality,
            lastActionIdx: state.defenderActions.length > 0
                ? DEFENDER_ACTION_IDS.indexOf(state.defenderActions[state.defenderActions.length - 1])
                : 0
        }, rlActionResult.actionIdx, reward, nextState, attackPrevented || state.currentTacticIdx >= TACTIC_PHASES.length - 1);
    }

    // ── 12. Record step ──
    const stepResult = {
        timestep: t,
        tacticId: currentTacticId,
        tacticName: currentTactic.name,
        tacticPhase: state.currentTacticIdx,
        technique: {
            id: technique.id,
            name: technique.name,
            detectionDifficulty: technique.detectionDifficulty,
            stealthRating: technique.stealthRating
        },
        detected,
        observedTechniqueId,
        observedTechniqueName: observedTechniqueId ? TECHNIQUE_BY_ID[observedTechniqueId]?.name : null,
        belief: { ...state.belief },
        beliefEntropy: getBeliefEntropy(state.belief),
        mostProbableType: getMostProbableType(state.belief),
        predictions,
        defenderAction: {
            id: defenderActionId,
            name: DEFENDER_ACTIONS[defenderActionId].name,
            isRL: isRLAction,
            isExploration,
            cost: DEFENDER_ACTIONS[defenderActionId].cost,
            disruption: DEFENDER_ACTIONS[defenderActionId].disruption
        },
        gameAnalysis,
        defenderUtility: Math.round(defUtil * 100) / 100,
        attackerUtility: Math.round(atkUtil * 100) / 100,
        reward: Math.round(reward * 100) / 100,
        attackPrevented,
        cumulativeDefenderUtility: Math.round(state.cumulativeDefenderUtility * 100) / 100,
        cumulativeAttackerUtility: Math.round(state.cumulativeAttackerUtility * 100) / 100
    };

    state.history.push(stepResult);
    state.defenderActions.push(defenderActionId);
    state.attackerTechniques.push(technique.id);
    state.detections.push(detected);
    state.timestep++;

    // ── 13. State transition ──
    if (attackPrevented) {
        // Attack prevented — check if attacker retries or pivots
        const retries = shouldProgress(attackerType, currentTacticId, true);
        if (retries) {
            state.currentTacticIdx = Math.min(state.currentTacticIdx + 1, TACTIC_PHASES.length - 1);
        }
        // If !retries, stays at same tactic (retry)
    } else {
        // Attack succeeded — progress to next tactic
        const progresses = shouldProgress(attackerType, currentTacticId, false);
        if (progresses) {
            state.currentTacticIdx = Math.min(state.currentTacticIdx + 1, TACTIC_PHASES.length - 1);
        }
    }

    // ── 14. Check game over ──
    if (state.timestep >= config.maxSteps || state.currentTacticIdx >= TACTIC_PHASES.length - 1) {
        state.gameOver = true;
        state.metrics = computeMetrics(state);
    }

    return stepResult;
}

/**
 * Run a complete episode from start to finish
 */
export function runEpisode(config, rlAgent = null) {
    const state = initSimulation(config);

    while (!state.gameOver) {
        stepSimulation(state, rlAgent);
    }

    if (!state.metrics) {
        state.metrics = computeMetrics(state);
    }

    return state;
}

/**
 * Run multiple training episodes for the RL agent
 */
export function runTraining(config, numEpisodes, rlAgent = null, progressCallback = null) {
    const agent = rlAgent || createAgent();
    const trainingLog = [];

    for (let ep = 0; ep < numEpisodes; ep++) {
        const state = runEpisode(config, agent);
        recordEpisodeReward(agent, state.cumulativeDefenderUtility);
        decayEpsilon(agent);

        trainingLog.push({
            episode: ep,
            cumulativeReward: Math.round(state.cumulativeDefenderUtility * 100) / 100,
            detectionRate: state.metrics.detectionRate,
            preventionRate: state.metrics.preventionRate,
            epsilon: agent.currentEpsilon,
            steps: state.timestep
        });

        if (progressCallback && ep % 10 === 0) {
            progressCallback(ep, numEpisodes, getAgentStats(agent), trainingLog);
        }
    }

    return {
        agent,
        stats: getAgentStats(agent),
        trainingLog
    };
}

/**
 * Compute SOC-relevant metrics at end of episode
 */
function computeMetrics(state) {
    const totalSteps = state.history.length;
    if (totalSteps === 0) {
        return {
            detectionRate: 0, preventionRate: 0, falsePositiveRate: 0,
            avgDefenderUtility: 0, avgAttackerUtility: 0,
            costEfficiency: 0, timeToDetection: -1, tacticsReached: 0,
            maxTacticPhase: 0
        };
    }

    // Detection rate: fraction of steps where attacker was detected
    const detections = state.history.filter(s => s.detected).length;
    const detectionRate = detections / totalSteps;

    // Prevention rate: fraction of steps where attack was prevented
    const preventions = state.history.filter(s => s.attackPrevented).length;
    const preventionRate = preventions / totalSteps;

    // Time to first detection (steps)
    const firstDetection = state.history.findIndex(s => s.detected);
    const timeToDetection = firstDetection >= 0 ? firstDetection : -1;

    // Average utilities
    const avgDefUtil = state.cumulativeDefenderUtility / totalSteps;
    const avgAtkUtil = state.cumulativeAttackerUtility / totalSteps;

    // Cost efficiency: total defender utility / total cost spent
    const totalCost = state.history.reduce((s, h) => s + h.defenderAction.cost, 0);
    const costEfficiency = totalCost > 0 ? state.cumulativeDefenderUtility / totalCost : 0;

    // Total disruption impact
    const totalDisruption = state.history.reduce((s, h) => s + h.defenderAction.disruption, 0);

    // Tactics reached by attacker
    const tacticsReached = new Set(state.history.map(h => h.tacticId)).size;
    const maxTacticPhase = Math.max(...state.history.map(h => h.tacticPhase));

    // False positive estimate (actions taken when no detection)
    const fpActions = state.history.filter(s => !s.detected && s.defenderAction.id !== 'monitor' && s.defenderAction.id !== 'accept_risk').length;
    const falsePositiveRate = totalSteps > 0 ? fpActions / totalSteps : 0;

    return {
        totalSteps,
        detectionRate: Math.round(detectionRate * 100) / 100,
        preventionRate: Math.round(preventionRate * 100) / 100,
        falsePositiveRate: Math.round(falsePositiveRate * 100) / 100,
        avgDefenderUtility: Math.round(avgDefUtil * 100) / 100,
        avgAttackerUtility: Math.round(avgAtkUtil * 100) / 100,
        costEfficiency: Math.round(costEfficiency * 100) / 100,
        totalCost: Math.round(totalCost * 100) / 100,
        totalDisruption: Math.round(totalDisruption * 100) / 100,
        timeToDetection,
        tacticsReached,
        maxTacticPhase,
        cumulativeDefenderUtility: Math.round(state.cumulativeDefenderUtility * 100) / 100,
        cumulativeAttackerUtility: Math.round(state.cumulativeAttackerUtility * 100) / 100
    };
}

/**
 * Export simulation state as a structured report
 */
export function exportSimulationReport(state) {
    return {
        config: {
            attackerType: state.config.attackerType,
            attackerName: ATTACKER_PROFILES[state.config.attackerType]?.name || state.config.attackerType,
            detectionCoverage: state.config.detectionCoverage,
            maxSteps: state.config.maxSteps,
            useRL: state.config.useRL,
            useGameTheory: state.config.useGameTheory
        },
        metrics: state.metrics,
        history: state.history,
        finalBelief: state.belief,
        attackerTechniques: state.attackerTechniques,
        defenderActions: state.defenderActions
    };
}
