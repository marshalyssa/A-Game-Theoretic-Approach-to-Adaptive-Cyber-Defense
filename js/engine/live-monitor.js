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
import { computeGlobalMultiThreatResponse } from './multi-agent-sim.js';

/**
 * Create a new live analysis session
 * @returns {Object} session state
 */
export function createLiveSession() {
    return {
        sessionId: `live_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
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
        },
        threatClusters: {} // Network vs Host vs Unknown clusters for Multi-Agent analysis
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

    // Assign to Threat Cluster (Multi-Agent Live Support)
    const clusterClass = (iocType === 'ip' || iocType === 'domain' || iocType === 'url') ? 'network' : 'host';
    if (!session.threatClusters[clusterClass]) {
        session.threatClusters[clusterClass] = {
            belief: createBeliefState(),
            killChainCoverage: {},
            lastTactic: null
        };
    }
    const cluster = session.threatClusters[clusterClass];
    for (const techId of techniqueIds) {
        cluster.belief = updateBelief(cluster.belief, techId);
        cluster.killChainCoverage[tacticStage] = true;
        cluster.lastTactic = tacticStage;
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
        recommendations = rankDefenderActions(predictions, session.metrics.detectionCoverage || 0.6);
        
        // Extract semantic threat context
        let contextStr = 'the observed malicious activity';
        if (directTechniques && directTechniques.length > 0) {
            contextStr = directTechniques.map(t => t.name).slice(0,2).join(' and ');
        } else if (mappedTechniques && mappedTechniques.length > 0) {
            contextStr = mappedTechniques.map(t => t.name).slice(0,2).join(' and ');
        } else if (enrichment?.results?.abuseipdb?.categories?.length > 0) {
            contextStr = enrichment.results.abuseipdb.categories.slice(0,2).join(' or ');
        }

        // Map abstract actions to NLP descriptions (Short & professional)
        recommendations = recommendations.map(action => {
            let newName = action.name;
            switch(action.actionId) {
                case 'monitor': newName = `Monitor connections involving ${ioc}.`; break;
                case 'block_ip': newName = `Block ${ioc} at the perimeter firewall.`; break;
                case 'isolate_host': newName = `Isolate internal hosts communicating with ${ioc}.`; break;
                case 'patch_vuln': newName = `Patch systems vulnerable to ${contextStr}.`; break;
                case 'deploy_edr': newName = `Ensure EDR coverage on hosts exposed to ${ioc}.`; break;
                case 'hunt_threat': newName = `Hunt for ${contextStr} lateral movement from ${ioc}.`; break;
                case 'deceive_honeypot': newName = `Deploy ${contextStr} decoys to observe ${ioc}.`; break;
                case 'restrict_network': newName = `Segment network to prevent ${ioc} propagation.`; break;
                case 'update_siem_rules': newName = `Deploy SIEM rules for ${contextStr} matching ${ioc}.`; break;
                case 'rotate_credentials': newName = `Rotate compromised credentials preventing ${contextStr}.`; break;
                case 'backup': newName = `Verify backups to prevent ${contextStr} impact.`; break;
                case 'incident_response': newName = `Activate IR playbooks for ${ioc} infiltration.`; break;
                case 'educate_users': newName = `Alert users to ${contextStr} attempts.`; break;
                case 'full_lockdown': newName = `Initiate immediate zero-trust lockdown.`; break;
                case 'accept_risk': newName = `Log ${contextStr} as a low-fidelity risk.`; break;
                default: newName = `Evaluate ${action.name} for ${ioc}.`; break;
            }
            return { ...action, name: newName };
        }).slice(0, 6);
    }
    session.recommendations = recommendations;

    // Step 7: Global Multi-Agent Optimization
    // Combines the separate Network and Host threat clusters to find one globally robust action
    const activeClusters = Object.values(session.threatClusters);
    if (activeClusters.length > 1) {
        session.globalMultiAgentStrategy = computeGlobalMultiThreatResponse(activeClusters);
        
        // Format the global action name for the UI
        try {
            const { DEFENDER_ACTIONS } = await import('../data/defender-actions.js');
            const gid = session.globalMultiAgentStrategy.bestAction;
            if (DEFENDER_ACTIONS[gid]) {
                session.globalMultiAgentStrategy.bestGlobalAction = `Enforce global ${DEFENDER_ACTIONS[gid].name} logic addressing ${activeClusters.length} concurrent clusters`;
            }
        } catch (e) {
            session.globalMultiAgentStrategy.bestGlobalAction = session.globalMultiAgentStrategy.bestAction;
        }
    }

    // Step 8: Update Session Metrics
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

    // ─── Step 9: Persist to Database ───────────────────────────────────────
    try {
        const persistPayload = {
            sessionId: session.sessionId,
            ioc,
            type: iocType,
            threat,
            tacticStage,
            mostProbableType: getMostProbableType(session.belief),
            beliefEntropy: getBeliefEntropy(session.belief),
            mappedTechniques,
            enrichment,
            feedsUsed: feeds,
            topAction: recommendations.length > 0 ? recommendations[0].name : ''
        };
        fetch('/api/ioc/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(persistPayload)
        }).catch(() => {}); // fire-and-forget

        // ─── Step 10: Generate RL Experience Tuple ─────────────────────────
        if (recommendations.length > 0 && techniqueIds.length > 0) {
            const beliefBucket = Math.round(getBeliefEntropy(session.belief) * 10);
            const phase = tacticStage.phase || 0;
            const severity = threat.score >= 70 ? 2 : threat.score >= 30 ? 1 : 0;
            const stateKey = `${phase}_${beliefBucket}_${severity}_1_0`;

            // Reward: higher for detecting threats, penalize missed high-risk IOCs
            const reward = (threat.score / 100) * 2 - 0.5 + (techniqueIds.length * 0.1);

            // Next state: advanced phase or terminal
            const nextPhase = Math.min(phase + 1, 13);
            const nextStateKey = `${nextPhase}_${beliefBucket}_${severity}_1_0`;

            const rlExp = {
                sessionId: session.sessionId,
                step: session.iocs.length,
                stateKey,
                actionIdx: 0, // First recommended action
                reward: Math.round(reward * 100) / 100,
                nextStateKey,
                done: false
            };
            fetch('/api/ioc/rl-experience', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(rlExp)
            }).catch(() => {}); // fire-and-forget
        }
    } catch (e) {
        // Persistence errors should never break analysis
        console.warn('IOC persistence failed:', e.message);
    }

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
