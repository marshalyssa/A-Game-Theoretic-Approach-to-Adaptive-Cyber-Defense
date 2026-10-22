import fs from 'fs';
import path from 'path';
import 'dotenv/config';

import { createBeliefState, updateBeliefBatch, getBeliefEntropy, getMostProbableType, getTopPredictions } from '../js/engine/bayesian-engine.js';
import { mapIOCToTechniques } from '../js/engine/ioc-mapper.js';
import { rankDefenderActions } from '../js/engine/game-engine.js';
import { createAgent, updateQValue, exportQTable, importQTable, discretizeBelief, stateToKey } from '../js/engine/rl-agent.js';
import { DEFENDER_ACTION_IDS } from '../js/data/defender-actions.js';

// db-manager is CommonJS
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const db = require('../js/engine/db-manager.cjs');

// Ensure DB is initialized
db.initDB();

const QTABLE_FILE = path.join(process.cwd(), 'data', 'q-table.json');

// Helper to determine IOC type
function identifyIOCType(ioc) {
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ioc)) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(ioc)) return 'md5';
    if (/^[a-fA-F0-9]{40}$/.test(ioc)) return 'sha1';
    if (/^[a-fA-F0-9]{64}$/.test(ioc)) return 'sha256';
    if (/^https?:\/\//.test(ioc)) return 'url';
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) return 'domain';
    return 'unknown';
}

async function fetchOTXPulses(limit = 5) {
    const apiKey = process.env.OTX_API_KEY;
    if (!apiKey) {
        console.warn('⚠️ OTX_API_KEY not found. Skipping OTX.');
        return [];
    }

    console.log(`📡 Fetching ${limit} recent subscribed pulses from OTX...`);
    try {
        const res = await fetch(`https://otx.alienvault.com/api/v1/pulses/subscribed?limit=${limit}`, {
            headers: { 'X-OTX-API-KEY': apiKey }
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        
        const iocs = new Set();
        for (const pulse of data.results || []) {
            for (const ind of pulse.indicators || []) {
                iocs.add(ind.indicator);
            }
        }
        return Array.from(iocs);
    } catch (err) {
        console.error('❌ Failed to fetch OTX pulses:', err.message);
        return [];
    }
}

async function fetchAbuseIPDBBlacklist(limit = 10) {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
        console.warn('⚠️ ABUSEIPDB_API_KEY not found. Skipping AbuseIPDB blacklist.');
        return [];
    }

    console.log(`📡 Fetching top ${limit} IPs from AbuseIPDB Blacklist...`);
    try {
        const res = await fetch(`https://api.abuseipdb.com/api/v2/blacklist?limit=${limit}`, {
            headers: { 'Key': apiKey, 'Accept': 'application/json' }
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        
        return (data.data || []).map(entry => entry.ipAddress);
    } catch (err) {
        console.error('❌ Failed to fetch AbuseIPDB blacklist:', err.message);
        return [];
    }
}

async function fetchRepoIOCs(limit = 50) {
    console.log(`📡 Fetching curated IOCs from marshalyssa/TIFeeds repo...`);
    try {
        const res = await fetch('https://raw.githubusercontent.com/marshalyssa/TIFeeds/main/all.csv');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const csv = await res.text();
        
        const lines = csv.split('\n').filter(l => l.trim() && !l.startsWith('indicator,'));
        const iocs = lines.map(line => {
            const parts = line.split(',');
            return parts[0];
        });

        // Unique and Shuffle
        return Array.from(new Set(iocs)).sort(() => 0.5 - Math.random()).slice(0, limit);
    } catch (err) {
        console.error('❌ Failed to fetch Repo IOCs:', err.message);
        return [];
    }
}

async function lookupIOC(ioc, type) {
    try {
        // Use all available feeds including the new no-auth ones
        const availableFeeds = ['otx', 'virustotal', 'abuseipdb', 'threatfox', 'malwarebazaar', 'ipapi'];
        const res = await fetch('http://127.0.0.1:3000/api/cti/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ioc, type, feeds: availableFeeds })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (e) {
        console.warn(`⚠️ Lookup failed for ${ioc}: ${e.message}`);
        return null;
    }
}

async function run() {
    console.log('──────────────────────────────────────────────────');
    console.log('🤖 Auto-Training RL Agent from TI Feeds');
    console.log('──────────────────────────────────────────────────\n');

    // Parse CLI arguments
    const args = process.argv.slice(2);
    const numPulses = args.includes('--pulses') ? parseInt(args[args.indexOf('--pulses') + 1]) : 2;
    const maxIocs = args.includes('--max-iocs') ? parseInt(args[args.indexOf('--max-iocs') + 1]) : 20;
    const isDryRun = args.includes('--dry-run');

    // Load existing Q-table if available
    const rlAgent = createAgent();
    if (!isDryRun && fs.existsSync(QTABLE_FILE)) {
        try {
            const data = JSON.parse(fs.readFileSync(QTABLE_FILE, 'utf-8'));
            importQTable(rlAgent, data);
            console.log(`🧠 Loaded existing Q-table with ${Object.keys(rlAgent.qTable).length} states and ${rlAgent.episodeCount} episodes.`);
        } catch (e) {
            console.warn('⚠️ Failed to load existing Q-table, starting fresh.');
        }
    }

    // 1. Fetch IOCs
    const otxIocs = await fetchOTXPulses(numPulses);
    const abuseIocs = await fetchAbuseIPDBBlacklist(Math.min(10, maxIocs));
    const repoIocs = await fetchRepoIOCs(maxIocs * 2);
    
    // Deduplicate and filter unknown types
    let allIocs = Array.from(new Set([...otxIocs, ...abuseIocs, ...repoIocs]))
        .map(ioc => ({ ioc, type: identifyIOCType(ioc) }))
        .filter(entry => entry.type !== 'unknown');
    
    // Shuffle and cap
    allIocs = allIocs.sort(() => 0.5 - Math.random()).slice(0, maxIocs);

    if (allIocs.length === 0) {
        console.log('❌ No valid IOCs found to process. Exiting.');
        return;
    }

    console.log(`\n🎯 Found ${allIocs.length} unique IOCs to process (capped at ${maxIocs}).\n`);

    if (isDryRun) {
        console.log('🛑 --dry-run enabled. Exiting before processing.');
        return;
    }

    // Generate a unique session ID for this auto-train batch
    const sessionId = `auto_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    let belief = createBeliefState();
    let processedCount = 0;
    let rlExperienceCount = 0;

    // 2. Process each IOC
    for (let i = 0; i < allIocs.length; i++) {
        const { ioc, type } = allIocs[i];
        console.log(`[${i + 1}/${allIocs.length}] Analyzing ${type.toUpperCase()}: ${ioc}`);

        // A. CTI Lookup (via server proxy)
        const enrichment = await lookupIOC(ioc, type);
        if (!enrichment) {
            // Wait to avoid hammering the server
            await new Promise(r => setTimeout(r, 1000));
            continue;
        }

        // B. Mapper Layer
        const mappedTechniques = mapIOCToTechniques(enrichment);
        const techniqueIds = mappedTechniques.map(t => t.techniqueId);

        // C. Bayesian Layer
        const observations = techniqueIds.map(id => ({ id, detected: true }));
        belief = updateBeliefBatch(belief, observations);
        const entropy = getBeliefEntropy(belief);
        const mostProbable = getMostProbableType(belief);

        // Determine tactic stage / threat severity based on mapped techniques
        // Simplified heuristic since we don't have the full session timeline
        let maxPhase = 0;
        let threatScore = 0;
        for (const tech of mappedTechniques) {
            if (tech.tacticPhase > maxPhase) maxPhase = tech.tacticPhase;
            threatScore += 10; 
        }
        
        // Add reputation modifiers
        if (enrichment.results?.otx?.reputation?.threat_score) {
            threatScore += enrichment.results.otx.reputation.threat_score;
        }
        if (enrichment.results?.abuseipdb?.abuseConfidenceScore) {
            threatScore += enrichment.results.abuseipdb.abuseConfidenceScore;
        }
        if (enrichment.results?.virustotal?.malicious > 0) {
            threatScore += (enrichment.results.virustotal.malicious * 10);
        }
        threatScore = Math.min(100, threatScore);
        
        let severityClass = 'NONE';
        if (threatScore >= 70) severityClass = 'CRITICAL';
        else if (threatScore >= 40) severityClass = 'HIGH';
        else if (threatScore >= 20) severityClass = 'ELEVATED';

        const tacticStage = {
            id: mappedTechniques.length > 0 ? mappedTechniques[mappedTechniques.length - 1].tacticId : 'TA0043',
            name: mappedTechniques.length > 0 ? mappedTechniques[mappedTechniques.length - 1].tacticName : 'Reconnaissance',
            phase: maxPhase
        };

        const severity = threatScore >= 70 ? 2 : threatScore >= 30 ? 1 : 0;
        
        // D. Game Theory Layer
        let recommendations = [];
        
        // Get predicted techniques from Bayes Engine to feed into Game Engine
        const lastTechId = techniqueIds.length > 0 ? techniqueIds[techniqueIds.length - 1] : 'T1595'; // Active Scanning as fallback
        const topPreds = getTopPredictions(belief, lastTechId, 5);
        
        if (topPreds.length > 0) {
            const predDist = {};
            for (const pred of topPreds) {
                predDist[pred.id] = pred.probability;
            }
            // rankDefenderActions returns [{actionId, name, expectedUtility, ...}]
            recommendations = rankDefenderActions(predDist, 0.5).slice(0, 5);
        }

        // E. Persistence (SQLite)
        try {
            db.saveIOCAnalysis({
                sessionId,
                ioc,
                type,
                threat: { score: threatScore, level: severityClass },
                tacticStage,
                mostProbableType: mostProbable,
                beliefEntropy: entropy,
                mappedTechniques,
                enrichment,
                feedsUsed: ['otx', 'virustotal', 'abuseipdb', 'threatfox', 'malwarebazaar', 'ipapi'],
                topAction: recommendations.length > 0 ? recommendations[0].name : ''
            });
            processedCount++;
        } catch (e) {
            console.error('   ❌ Database error:', e.message);
        }

        // F. RL Experience Tuple
        if (recommendations.length > 0 && (techniqueIds.length > 0 || threatScore >= 20)) {
            const beliefBucket = discretizeBelief(belief);
            const stateKey = stateToKey(tacticStage.phase, beliefBucket, severity, 1, 0);

            const reward = (threatScore / 100) * 2 - 0.5 + (techniqueIds.length * 0.1);
            const nextPhase = Math.min(tacticStage.phase + 1, 13);
            const nextStateKey = stateToKey(nextPhase, beliefBucket, severity, 1, 0);

            const actionId = recommendations[0].actionId;
            const actionIdx = DEFENDER_ACTION_IDS.indexOf(actionId);

            try {
                db.saveRLExperience({
                    sessionId,
                    step: i,
                    stateKey,
                    actionIdx,
                    reward: Math.round(reward * 100) / 100,
                    nextStateKey,
                    done: false
                });
                rlExperienceCount++;
            } catch (e) {
                console.error('   ❌ RL DB error:', e.message);
            }
        }

        // Prevent hitting API rate limits
        if (i < allIocs.length - 1) {
            await new Promise(r => setTimeout(r, 1500));
        }
    }

    console.log(`\n✅ Finished Processing: ${processedCount}/${allIocs.length} IOCs stored.`);

    // 3. Replay RL Experiences
    if (rlExperienceCount > 0) {
        console.log(`\n🧠 Replaying ${rlExperienceCount} new RL experiences into Q-table...`);
        const exps = db.getRLExperiences(500); // Fetch latest from DB
        let replayed = 0;
        for (const exp of exps) {
             updateQValue(rlAgent, exp.state_key, exp.action_idx, exp.reward, exp.next_state_key, !!exp.done);
             replayed++;
        }
        
        // 4. Save Q-Table
        try {
            if (!fs.existsSync(path.dirname(QTABLE_FILE))) {
                fs.mkdirSync(path.dirname(QTABLE_FILE), { recursive: true });
            }
            fs.writeFileSync(QTABLE_FILE, JSON.stringify(exportQTable(rlAgent), null, 2));
            console.log(`💾 Saved updated Q-table to ${QTABLE_FILE}`);
        } catch (e) {
            console.error('❌ Failed to save Q-table to disk:', e.message);
        }
        
        console.log(`🎯 Auto-training complete! Q-table states: ${Object.keys(rlAgent.qTable).length}`);
    } else {
        console.log('\nℹ️ No actionable RL experiences generated in this batch.');
    }
}

run();
