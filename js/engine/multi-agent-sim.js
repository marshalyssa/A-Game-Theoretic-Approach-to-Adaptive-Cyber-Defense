/**
 * Multi-Agent Live Monitor
 * 
 * Extends the Multi-Agent concept to the Live IOC pipeline.
 * Instead of synthetic simulation, it monitors multiple independent 
 * real-world threat streams (sessions or clusters) concurrently. 
 * Calculates global defensive strategies using marginal payouts across all active threats.
 */

import { TACTIC_PHASES, TECHNIQUES_BY_TACTIC } from '../data/mitre-catalog.js';
import { ATTACKER_TYPES, selectAttackerTechnique } from '../data/attacker-profiles.js';
import { bestMultiAgentResponse } from './game-engine.js';
import { rankDefenderActions } from './game-engine.js';

/**
 * Computes the optimal global action against multiple concurrent real-world threats
 * 
 * @param {Array<Object>} activeThreatSessions - Array of liveSession objects
 * @param {number} detectionCoverage - Target SOC coverage (0-1)
 * @returns {Object} Global Response Strategy
 */
export function computeGlobalMultiThreatResponse(activeThreatSessions, detectionCoverage = 0.6) {
    if (!activeThreatSessions || activeThreatSessions.length === 0) return null;

    const curBeliefs = [];
    const expTechs = [];
    
    for (const session of activeThreatSessions) {
        if (!session.belief) continue;
        curBeliefs.push(session.belief);
        
        // Map expected incoming techniques for each attacker profile based on this session's current tactic
        const techMap = {};
        const tacticId = session.killChainCoverage && Object.keys(session.killChainCoverage).length > 0 
            ? Object.keys(session.killChainCoverage).pop() 
            : TACTIC_PHASES[0];
            
        const availableTechs = TECHNIQUES_BY_TACTIC[tacticId] || [];
        
        for (const type of ATTACKER_TYPES) {
            // Using the game-theoretic attacker profile heuristic
            techMap[type] = selectAttackerTechnique(type, availableTechs, []);
        }
        expTechs.push(techMap);
    }

    if (curBeliefs.length === 0) return null;

    // Use Game Theory Engine to find globally optimal action marginalizing all beliefs
    const globalResponse = bestMultiAgentResponse(curBeliefs, expTechs, detectionCoverage);
    
    return {
        bestGlobalAction: globalResponse.bestAction,
        globalUtility: globalResponse.expectedUtility,
        activeThreatsCount: curBeliefs.length
    };
}
