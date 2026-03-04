/**
 * Live Monitor — Real-Time IOC Analysis Orchestrator
 * 
 * Manages the "Live Mode" workflow:
 * 1. User submits IOC(s)
 * 2. CTI feeds are queried for enrichment
 * 3. Enrichment mapped to ATT&CK techniques
 * 4. Bayesian engine updates belief based on observed techniques
 * 5. Game engine predicts next likely techniques
 * 6. Defender action recommendations generated
 */

import { lookupIOC, extractAttackTechniques, assessThreatLevel, detectIOCType } from './cti-manager.js';
import { mapIOCToTechniques, inferTacticStage } from './ioc-mapper.js';
import { createBeliefState, updateBelief, getBeliefEntropy, getMostProbableType, getTopPredictions } from './bayesian-engine.js';
import { rankDefenderActions } from './game-engine.js';

/**
 * Create a new live analysis session
 * @returns {Object} session state
 */
export function createLiveSession() {
    return {
        iocs: [],               // All submitted IOCs with enrichment
        belief: createBeliefState(),
        observedTechniques: [],  // All ATT&CK techniques mapped from IOCs
        predictions: [],         // Current predictions
        recommendations: [],     // Current defender recommendations
        timeline: [],            // Analysis timeline entries
        killChainCoverage: {},   // Which tactic stages have been observed
        metrics: {
            totalIOCs: 0,
            maliciousIOCs: 0,
            techniquesObserved: 0,
            highestThreat: 'NONE',
            avgThreatScore: 0
        }
    };
}

/**
 * Analyze a single IOC through the full pipeline
 * 
 * @param {Object} session - Live session state
 * @param {string} ioc - The indicator to analyze
 * @param {string} type - IOC type (auto-detected if not provided)
 * @param {string[]} feeds - CTI feeds to query
 * @param {Function} progressCallback - Called with progress updates
 * @returns {Object} Analysis result for this IOC
 */
export async function analyzeIOC(session, ioc, type = null, feeds = ['otx', 'virustotal', 'abuseipdb'], progressCallback = null) {
    const iocType = type || detectIOCType(ioc);

    // Step 1: CTI Enrichment
    if (progressCallback) progressCallback('enriching', `Querying CTI feeds for ${ioc}…`);

    const enrichment = await lookupIOC(ioc, iocType, feeds);

    // Step 2: Threat Assessment
    const threat = assessThreatLevel(enrichment);

    // Step 3: IOC → ATT&CK Mapping
    if (progressCallback) progressCallback('mapping', 'Mapping to MITRE ATT&CK techniques…');

    const mappedTechniques = mapIOCToTechniques(enrichment);
    const directTechniques = extractAttackTechniques(enrichment);
    const tacticStage = inferTacticStage(mappedTechniques);

    // Step 4: Bayesian Belief Update
    if (progressCallback) progressCallback('inference', 'Updating Bayesian belief state…');

    const techniqueIds = mappedTechniques.map(t => t.techniqueId);
    for (const techId of techniqueIds) {
        session.belief = updateBelief(session.belief, techId);
    }

    // Track observed techniques (deduplicated)
    for (const techId of techniqueIds) {
        if (!session.observedTechniques.includes(techId)) {
            session.observedTechniques.push(techId);
        }
    }

    // Step 5: Predict Next Techniques
    if (progressCallback) progressCallback('predicting', 'Predicting next adversary techniques…');

    let predictions = [];
    if (techniqueIds.length > 0) {
        // Use the highest-phase technique as the "last observed"
        const lastTech = techniqueIds[0]; // Highest confidence technique
        predictions = getTopPredictions(session.belief, lastTech, 5);
    }
    session.predictions = predictions;

    // Step 6: Game-Theoretic Recommendations
    if (progressCallback) progressCallback('recommending', 'Computing optimal defensive strategy…');

    let recommendations = [];
    if (predictions.length > 0) {
        const predDist = {};
        for (const pred of predictions) {
            predDist[pred.id] = pred.probability;
        }
        recommendations = rankDefenderActions(predDist, 0.5).slice(0, 5);
    }
    session.recommendations = recommendations;

    // Step 7: Update Session Metrics
    session.metrics.totalIOCs++;
    if (threat.level === 'HIGH' || threat.level === 'CRITICAL') {
        session.metrics.maliciousIOCs++;
    }
    session.metrics.techniquesObserved = session.observedTechniques.length;
    if (threatLevelRank(threat.level) > threatLevelRank(session.metrics.highestThreat)) {
        session.metrics.highestThreat = threat.level;
    }
    session.metrics.avgThreatScore = Math.round(
        (session.metrics.avgThreatScore * (session.metrics.totalIOCs - 1) + threat.score) / session.metrics.totalIOCs
    );

    // Step 8: Build timeline entry
    const entry = {
        timestamp: new Date().toISOString(),
        ioc,
        type: iocType,
        enrichment,
        threat,
        mappedTechniques,
        directTechniques,
        tacticStage,
        belief: { ...session.belief },
        beliefEntropy: getBeliefEntropy(session.belief),
        mostProbableType: getMostProbableType(session.belief),
        predictions,
        recommendations,
    };

    session.iocs.push(entry);
    session.timeline.push(entry);

    // Update kill chain coverage
    for (const tech of mappedTechniques) {
        if (!session.killChainCoverage[tech.tacticId]) {
            session.killChainCoverage[tech.tacticId] = [];
        }
        if (!session.killChainCoverage[tech.tacticId].includes(tech.techniqueId)) {
            session.killChainCoverage[tech.tacticId].push(tech.techniqueId);
        }
    }

    if (progressCallback) progressCallback('complete', 'Analysis complete');

    return entry;
}

/**
 * Analyze multiple IOCs in batch
 * @param {Object} session - Live session state
 * @param {Array<{ioc: string, type: string}>} iocList - IOCs to analyze
 * @param {string[]} feeds - CTI feeds
 * @param {Function} progressCallback - Progress updates
 * @returns {Array} Analysis results
 */
export async function analyzeBatch(session, iocList, feeds, progressCallback = null) {
    const results = [];

    for (let i = 0; i < iocList.length; i++) {
        const { ioc, type } = iocList[i];
        if (progressCallback) {
            progressCallback('batch', `Analyzing IOC ${i + 1} of ${iocList.length}: ${ioc}`);
        }

        const result = await analyzeIOC(session, ioc, type, feeds);
        results.push(result);

        // Small delay between API calls to respect rate limits
        if (i < iocList.length - 1) {
            await new Promise(r => setTimeout(r, 300));
        }
    }

    return results;
}

/**
 * Get a summary of the current session for display
 */
export function getSessionSummary(session) {
    return {
        metrics: session.metrics,
        belief: session.belief,
        entropy: getBeliefEntropy(session.belief),
        mostProbableType: getMostProbableType(session.belief),
        observedTechniques: session.observedTechniques,
        predictions: session.predictions,
        recommendations: session.recommendations,
        killChainCoverage: session.killChainCoverage,
        timelineLength: session.timeline.length
    };
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function threatLevelRank(level) {
    return { 'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4 }[level] || 0;
}
