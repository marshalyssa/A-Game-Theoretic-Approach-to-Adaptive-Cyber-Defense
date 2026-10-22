/**
 * App Controller — UI Wiring, Rendering, and IOC Analysis Control
 * 
 * Live IOC Mode: Submit real IOCs, query CTI feeds, map to ATT&CK,
 * predict next steps, and train RL agents from historical data.
 */

import { TACTICS, TECHNIQUE_BY_ID, TACTIC_PHASES } from './data/mitre-catalog.js';
import { ATTACKER_PROFILES, ATTACKER_TYPES } from './data/attacker-profiles.js';
import { DEFENDER_ACTIONS, DEFENDER_ACTION_IDS } from './data/defender-actions.js';
import { createBeliefState, getBeliefEntropy, getMaxEntropy } from './engine/bayesian-engine.js';
import { computePayoffMatrix, solveMixedStrategy } from './engine/game-engine.js';
import { createAgent, getAgentStats, resetAgent, trainFromReplayBatch, exportQTable, importQTable } from './engine/rl-agent.js';
import { createDQNAgent, getDQNAgentStats, trainFromIOCReplay, exportDQNNetwork, importDQNNetwork } from './engine/dqn-agent.js';
// ─── Global State ──────────────────────────────────────────────────────────
let rlAgent = createAgent();
let dqnAgent = createDQNAgent();
let isRunning = false;
let currentMode = 'live'; // 'live' | 'history'
let liveSession = null;

// ─── DOM References ────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const DOM = {
    // Tabs
    tabLive: $('tab-live'),
    tabHistory: $('tab-history'),
    // IOC panels
    iocPanel: $('ioc-panel'),
    iocInput: $('ioc-input'),
    feedOTX: $('feed-otx'),
    feedVT: $('feed-vt'),
    feedAbuse: $('feed-abuse'),
    btnAnalyze: $('btn-analyze'),
    btnClearIOC: $('btn-clear-ioc'),
    btnIOCHistory: $('btn-ioc-history'),
    btnTrainIOC: $('btn-train-ioc'),
    dbStatsBadge: $('db-stats-badge'),
    feedStatusBadge: $('feed-status-badge'),
    enrichmentPanel: $('enrichment-panel'),
    enrichmentContent: $('enrichment-content'),
    // Live metrics
    liveMetricsRow: $('live-metrics-row'),
    lmIOCs: $('lm-iocs'),
    lmMalicious: $('lm-malicious'),
    lmTechniques: $('lm-techniques'),
    lmThreat: $('lm-threat'),
    lmScore: $('lm-score'),
    // Timeline & techniques
    iocTimelinePanel: $('ioc-timeline-panel'),
    iocTimelineBody: $('ioc-timeline-body'),
    iocCountBadge: $('ioc-count-badge'),
    mappedTechniquesPanel: $('mapped-techniques-panel'),
    mappedTechniquesList: $('mapped-techniques-list'),
    predictionsPanel: $('predictions-panel'),
    predictionsList: $('predictions-list'),
    actionsPanel: $('actions-panel'),
    actionsList: $('actions-list'),
    // RL Training panel
    rlTrainingPanel: $('rl-training-panel'),
    rlExpCount: $('rl-exp-count'),
    btnTrainQL: $('btn-train-ql'),
    btnTrainDQN: $('btn-train-dqn'),
    rlTrainOutput: $('rl-train-output'),
    rlStatsGrid: $('rl-stats-grid'),
    // History metrics
    hmTotalIocs: $('hm-total-iocs'),
    hmMaliciousIocs: $('hm-malicious-iocs'),
    hmAvgScore: $('hm-avg-score'),
    
    // Feed analytics containers
    vtHistoryChart: $('vt-history-chart'),
    abuseHistoryChart: $('abuse-history-chart'),
    otxHistoryChart: $('otx-history-chart'),

    // History 
    historyTabContent: $('history-tab-content'),
    historyIocTbody: $('history-ioc-tbody'),
    historyIocSearch: $('ioc-history-search')
};

let lastFetchedHistory = [];

// Live-only panels
const LIVE_PANELS = ['ioc-panel', 'enrichment-panel', 'live-metrics-row', 'ioc-timeline-panel', 'mapped-techniques-panel', 'predictions-panel', 'actions-panel', 'rl-training-panel'];
// Shared panels
const SHARED_PANELS = ['killchain-panel', 'belief-panel'];

// ─── Initialize ────────────────────────────────────────────────────────────
function init() {
    bindEvents();
    switchTab('live'); // Default to live mode
    loadSavedRLState();
}

// ─── Toast Notifications ───────────────────────────────────────────────────
window.showError = function (msg) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
        <div class="toast-icon">⚠️</div>
        <div class="toast-content">${msg}</div>
    `;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 300);
    }, 6000);
};

// ─── Tab Switching ─────────────────────────────────────────────────────────
function switchTab(mode) {
    currentMode = mode;

    // Update tab buttons
    if (DOM.tabLive) DOM.tabLive.classList.toggle('active', mode === 'live');
    if (DOM.tabHistory) DOM.tabHistory.classList.toggle('active', mode === 'history');

    for (const id of LIVE_PANELS) {
        const el = document.getElementById(id);
        if (el) {
            el.style.display = mode === 'live' ? '' : 'none';
            if (mode === 'live') el.classList.add('fade-in');
            else el.classList.remove('fade-in');
        }
    }
    
    if (DOM.historyTabContent) {
        DOM.historyTabContent.style.display = mode === 'history' ? 'block' : 'none';
        if (mode === 'history') DOM.historyTabContent.classList.add('fade-in');
    }

    // Load appropriate contextual data
    if (mode === 'live') {
        checkFeeds();
        refreshDBStats();
        if (!liveSession) {
            initLiveSession();
        }
    } else if (mode === 'history') {
        showIOCHistory();
    }
}

async function checkFeeds() {
    try {
        const { checkFeedStatus } = await import('./engine/cti-manager.js');
        const feeds = await checkFeedStatus();
        const count = [feeds.otx, feeds.virustotal, feeds.abuseipdb].filter(Boolean).length;
        DOM.feedStatusBadge.textContent = `FEEDS: ${count}/3`;
        DOM.feedStatusBadge.className = `badge ${count >= 2 ? 'badge-green' : count >= 1 ? 'badge-amber' : 'badge-red'}`;
    } catch (e) {
        DOM.feedStatusBadge.textContent = 'FEEDS: ERR';
        DOM.feedStatusBadge.className = 'badge badge-red';
    }
}

async function initLiveSession() {
    const { createLiveSession } = await import('./engine/live-monitor.js');
    liveSession = createLiveSession();
}

function bindEvents() {
    // Tab switching
    if (DOM.tabLive) DOM.tabLive.addEventListener('click', () => switchTab('live'));
    if (DOM.tabHistory) DOM.tabHistory.addEventListener('click', () => switchTab('history'));

    // Text search filter for History
    if (DOM.historyIocSearch && DOM.historyIocTbody) {
        DOM.historyIocSearch.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const rows = Array.from(DOM.historyIocTbody.getElementsByTagName('tr'));
            
            // Filter visible rows
            rows.forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(query) ? '' : 'none';
            });
            
            // Recalculate analytics based on filtered raw data
            const filteredData = lastFetchedHistory.filter((_, i) => rows[i].style.display !== 'none');
            updateFeedAnalytics(filteredData);
        });
    }

    // IOC controls
    if (DOM.btnAnalyze) DOM.btnAnalyze.addEventListener('click', runIOCAnalysis);
    if (DOM.btnClearIOC) DOM.btnClearIOC.addEventListener('click', clearLiveSession);
    if (DOM.btnIOCHistory) DOM.btnIOCHistory.addEventListener('click', showIOCHistory);
    if (DOM.btnTrainIOC) DOM.btnTrainIOC.addEventListener('click', trainFromIOCs);

    // RL Training panel controls
    if (DOM.btnTrainQL) DOM.btnTrainQL.addEventListener('click', () => runRLTraining('ql'));
    if (DOM.btnTrainDQN) DOM.btnTrainDQN.addEventListener('click', () => runRLTraining('dqn'));
}



// ═══════════════════════════════════════════════════════════════════════════
//  LIVE IOC MODE
// ═══════════════════════════════════════════════════════════════════════════

async function runIOCAnalysis() {
    if (isRunning) return;

    const inputText = DOM.iocInput.value.trim();
    if (!inputText) return;

    isRunning = true;
    isRunning = true;
    DOM.btnAnalyze.disabled = true;

    // Get selected feeds
    const feeds = [];
    if (DOM.feedOTX.checked) feeds.push('otx');
    if (DOM.feedVT.checked) feeds.push('virustotal');
    if (DOM.feedAbuse.checked) feeds.push('abuseipdb');

    try {
        const { parseIOCInput } = await import('./engine/cti-manager.js');
        const { analyzeIOC } = await import('./engine/live-monitor.js');

        if (!liveSession) await initLiveSession();

        const iocList = parseIOCInput(inputText);
        if (iocList.length === 0) {
            isRunning = false;
            DOM.btnAnalyze.disabled = false;
            return;
        }

        // Show progress
        DOM.enrichmentContent.innerHTML = `
            <div style="text-align:center; padding: 20px;">
                <div style="color: var(--accent-cyan); margin-bottom: 8px;">🔍 Analyzing ${iocList.length} IOC(s)…</div>
                <div class="progress-bar"><div class="progress-bar-fill" id="analysis-progress" style="width:0%"></div></div>
            </div>
        `;

        const progressBar = $('analysis-progress');

        for (let i = 0; i < iocList.length; i++) {
            const { ioc, type } = iocList[i];

            const result = await analyzeIOC(liveSession, ioc, type, feeds, (stage, msg) => {
                if (progressBar) {
                    const pct = ((i + 0.5) / iocList.length) * 100;
                    progressBar.style.width = `${pct}%`;
                }
            });

            // Warn user about any feed-level errors (partial failures)
            const feedErrors = result.enrichment?.errors || {};
            for (const [feed, errMsg] of Object.entries(feedErrors)) {
                showError(`${feed.toUpperCase()} feed error: ${errMsg}`, 'warn', 6000);
            }

            // Render this IOC's result
            renderIOCResult(result, i + 1);
            renderLiveMetrics();
            updateBeliefUI(liveSession.belief);
            updateLiveKillChain(liveSession.killChainCoverage);

            // Render predictions and actions
            if (liveSession.predictions.length > 0) {
                renderLivePredictions(liveSession.predictions);
            }
            if (liveSession.recommendations.length > 0) {
                renderLiveActions(liveSession.recommendations);
            }

            // Small delay for rate limiting
            if (i < iocList.length - 1) await delay(500);
        }

        // Show final enrichment for last IOC
        const lastResult = liveSession.iocs[liveSession.iocs.length - 1];
        if (lastResult) renderEnrichment(lastResult.enrichment);

        // Status handled implicitly by enabled button
    } catch (e) {
        // Surface the error to the user via toast
        showError(`Analysis failed: ${e.message}`);
        DOM.enrichmentContent.innerHTML = `
            <div class="empty-state" style="color: var(--accent-red);">
                <div class="icon">⚠️</div>
                <p>Error: ${e.message}</p>
                <p style="font-size: 0.72rem; margin-top: 4px; color: var(--text-muted);">Make sure the server is running (node server.js) and API keys are configured.</p>
            </div>
        `;
        // Status handled implicitly by enabled button
    }

    isRunning = false;
    DOM.btnAnalyze.disabled = false;
}

function clearLiveSession() {
    liveSession = null;
    initLiveSession();
    updateBeliefUI(createBeliefState());
    resetKillChain();
    DOM.iocInput.value = '';
    DOM.iocTimelineBody.innerHTML = '';
    DOM.iocCountBadge.textContent = '0 IOCs';
    DOM.enrichmentContent.innerHTML = '<div class="empty-state"><div class="icon">📡</div><p>Submit IOCs to see enrichment</p></div>';
    DOM.mappedTechniquesList.innerHTML = '<div class="empty-state"><div class="icon">🗺</div><p>Submit IOCs to map techniques</p></div>';
    DOM.lmIOCs.textContent = '0';
    DOM.lmMalicious.textContent = '0';
    DOM.lmTechniques.textContent = '0';
    DOM.lmThreat.textContent = 'NONE';
    DOM.lmScore.textContent = '0';
    setStatus('idle', 'CLEARED');
}

// ─── IOC Database Features ─────────────────────────────────────────────────
async function refreshDBStats() {
    try {
        const resp = await fetch('/api/ioc/stats');
        const stats = await resp.json();
        if (DOM.dbStatsBadge) {
            DOM.dbStatsBadge.textContent = `DB: ${stats.totalIOCs} IOCs`;
        }
    } catch (e) {
        if (DOM.dbStatsBadge) DOM.dbStatsBadge.textContent = 'DB: offline';
    }
}

async function showIOCHistory() {
    try {
        if (!DOM.historyIocTbody) return;
        DOM.historyIocTbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 20px;">
            <div style="color: var(--accent-cyan); margin-bottom: 8px;">📊 Loading IOC History…</div>
            <div class="progress-bar"><div class="progress-bar-fill" style="width:50%"></div></div>
        </td></tr>`;

        const resp = await fetch('/api/ioc/history?limit=100');
        const history = await resp.json();
        lastFetchedHistory = history;

        if (!history || history.length === 0) {
            DOM.historyIocTbody.innerHTML = '<tr><td colspan="8" style="text-align:center;">No IOC history in database yet. Analyze some IOCs first!</td></tr>';
            updateFeedAnalytics([]);
            return;
        }

        let html = '';
        history.forEach((row, i) => {
            const threatClass = `threat-${row.threat_level || 'NONE'}`;
            html += `
                <tr class="animate-in" style="animation-delay: ${i * 10}ms">
                    <td>${i + 1}</td>
                    <td style="font-weight:600; color:var(--text-primary);">${row.ioc}</td>
                    <td><span class="source-tag">${row.type}</span></td>
                    <td><span class="threat-badge ${threatClass}">${row.threat_level || 'NONE'}</span></td>
                    <td style="color:${row.threat_score > 50 ? 'var(--accent-red)' : 'var(--text-secondary)'}">${row.threat_score}</td>
                    <td>${row.most_probable_type ? `<span style="color:var(--accent-purple)">${row.most_probable_type}</span>` : '—'}</td>
                    <td>${row.defender_action || '—'}</td>
                    <td style="font-size:0.75rem; color:var(--text-muted)">${new Date(row.timestamp).toLocaleDateString()}</td>
                </tr>
            `;
        });
        
        DOM.historyIocTbody.innerHTML = html;
        updateFeedAnalytics(history);
    } catch (e) {
        showError('Failed to load IOC history: ' + e.message);
        if (DOM.historyIocTbody) DOM.historyIocTbody.innerHTML = `<tr><td colspan="8" style="color:var(--accent-red);text-align:center;">Failed to load data</td></tr>`;
    }
}

async function updateFeedAnalytics(data) {
    if (!data || data.length === 0) {
        [DOM.vtHistoryChart, DOM.abuseHistoryChart, DOM.otxHistoryChart].forEach(el => {
            if (el) el.innerHTML = '<div class="empty-state-sm">No analysis history available</div>';
        });
        if (DOM.hmTotalIocs) DOM.hmTotalIocs.textContent = '0';
        if (DOM.hmMaliciousIocs) DOM.hmMaliciousIocs.textContent = '0';
        if (DOM.hmAvgScore) DOM.hmAvgScore.textContent = '0';
        return;
    }

    // 1. Basic Metrics
    const maliciousCount = data.filter(d => d.threat_level === 'HIGH' || d.threat_level === 'CRITICAL').length;
    const avgScore = Math.round(data.reduce((acc, d) => acc + (d.threat_score || 0), 0) / data.length);
    
    if (DOM.hmTotalIocs) DOM.hmTotalIocs.textContent = data.length;
    if (DOM.hmMaliciousIocs) DOM.hmMaliciousIocs.textContent = maliciousCount;
    if (DOM.hmAvgScore) DOM.hmAvgScore.textContent = avgScore;

    // 2. Feed Processing
    let vtDetections = 0;
    let vtTotal = 0;
    let abuseScores = [];
    let otxPulseTotal = 0;
    let processedVT = 0;
    let processedAbuse = 0;
    let processedOTX = 0;

    data.forEach(row => {
        try {
            const enrichment = JSON.parse(row.enrichment_json || '{}');
            
            // VT
            if (enrichment.results?.virustotal) {
                const vt = enrichment.results.virustotal;
                const stats = vt.data?.attributes?.last_analysis_stats || vt.attributes?.last_analysis_stats;
                if (stats) {
                    vtDetections += stats.malicious || 0;
                    vtTotal += (stats.malicious + stats.undetected + stats.suspicious) || 1;
                    processedVT++;
                }
            }

            // AbuseIPDB
            if (enrichment.results?.abuseipdb) {
                const abuse = enrichment.results.abuseipdb;
                if (abuse.abuseConfidenceScore !== undefined) {
                    abuseScores.push(abuse.abuseConfidenceScore);
                    processedAbuse++;
                }
            }

            // OTX
            if (enrichment.results?.otx) {
                const otx = enrichment.results.otx;
                const pulseCount = otx.pulse_info?.count || 0;
                otxPulseTotal += pulseCount;
                processedOTX++;
            }
        } catch (e) {
            console.warn("Failed to parse enrichment for row:", row.id);
        }
    });

    // 3. Render VT Gauge
    const vtPercent = processedVT > 0 ? Math.round((vtDetections / vtTotal) * 100) : 0;
    DOM.vtHistoryChart.innerHTML = `
        <div class="history-gauge">
            <div class="hg-value" style="background: linear-gradient(135deg, var(--accent-red), #ff7e5f); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">${vtPercent}%</div>
            <div class="hg-label">Detection Hit Rate</div>
            <div class="hg-sub">Aggregated across ${processedVT} engines</div>
        </div>
        <div class="history-meter">
            <div class="hm-track"><div class="hm-fill" style="width: ${vtPercent}%; background: var(--accent-red);"></div></div>
            <div class="hm-stats"><span>Clean</span><span>Malicious</span></div>
        </div>
    `;

    // 4. Render AbuseIPDB Gauge
    const avgAbuse = abuseScores.length > 0 ? Math.round(abuseScores.reduce((a, b) => a + b) / abuseScores.length) : 0;
    DOM.abuseHistoryChart.innerHTML = `
        <div class="history-gauge">
            <div class="hg-value" style="background: linear-gradient(135deg, var(--accent-amber), #feb47b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">${avgAbuse}</div>
            <div class="hg-label">Mean Confidence Score</div>
            <div class="hg-sub">Based on ${processedAbuse} unique reports</div>
        </div>
        <div class="history-meter">
            <div class="hm-track"><div class="hm-fill" style="width: ${avgAbuse}%; background: var(--accent-amber);"></div></div>
            <div class="hm-stats"><span>Safe</span><span>Reported</span></div>
        </div>
    `;

    // 5. Render OTX Gauge
    const avgPulses = processedOTX > 0 ? (otxPulseTotal / processedOTX).toFixed(1) : 0;
    DOM.otxHistoryChart.innerHTML = `
        <div class="history-gauge">
            <div class="hg-value" style="background: linear-gradient(135deg, var(--accent-purple), #8e2de2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">${avgPulses}</div>
            <div class="hg-label">Average Pulse Frequency</div>
            <div class="hg-sub">Threat community mentions</div>
        </div>
        <div class="history-meter">
            <div class="hm-track"><div class="hm-fill" style="width: ${Math.min(avgPulses * 10, 100)}%; background: var(--accent-purple);"></div></div>
            <div class="hm-stats"><span>Isolated</span><span>Trending</span></div>
        </div>
    `;
}

async function trainFromIOCs() {
    // Delegate to the RL training panel's Q-Learning trainer
    await runRLTraining('ql');
}

// ─── Render IOC Result ─────────────────────────────────────────────────────
function renderIOCResult(result, index) {
    // Timeline row
    const row = document.createElement('tr');
    row.className = 'animate-in';

    const techStr = result.mappedTechniques.slice(0, 3).map(t => t.techniqueId).join(', ');
    const srcSet = new Set();
    result.mappedTechniques.forEach(t => t.sources.forEach(s => srcSet.add(s.split(' ')[0])));
    const srcStr = [...srcSet].map(s => `<span class="source-tag">${s}</span>`).join('');

    row.innerHTML = `
        <td>${index}</td>
        <td title="${result.ioc}" style="max-width:140px;overflow:hidden;text-overflow:ellipsis;">${result.ioc}</td>
        <td>${result.type.toUpperCase()}</td>
        <td><span class="threat-badge threat-${result.threat.level}">${result.threat.level}</span></td>
        <td>${result.threat.score}</td>
        <td title="${result.mappedTechniques.map(t => t.techniqueId).join(', ')}">${techStr}${result.mappedTechniques.length > 3 ? '…' : ''}</td>
        <td>${result.tacticStage.tacticName}</td>
        <td>${formatTypeName(result.mostProbableType.type)} (${Math.round(result.mostProbableType.probability * 100)}%)</td>
        <td>${srcStr}</td>
    `;
    DOM.iocTimelineBody.appendChild(row);
    DOM.iocCountBadge.textContent = `${index} IOCs`;

    // Scroll
    const container = DOM.iocTimelineBody.closest('.trace-container');
    if (container) container.scrollTop = container.scrollHeight;

    // Update mapped techniques panel
    renderMappedTechniques(liveSession);
}

function renderMappedTechniques(session) {
    if (!session) return;

    // collect all techniques from all IOCs with highest confidence
    const techMap = {};
    for (const entry of session.iocs) {
        for (const tech of entry.mappedTechniques) {
            if (!techMap[tech.techniqueId] || tech.confidence > techMap[tech.techniqueId].confidence) {
                techMap[tech.techniqueId] = tech;
            }
        }
    }

    const sorted = Object.values(techMap).sort((a, b) => b.confidence - a.confidence);
    if (sorted.length === 0) return;

    DOM.mappedTechniquesList.innerHTML = '';
    sorted.forEach((tech, i) => {
        const el = document.createElement('div');
        el.className = 'prediction-item animate-in';
        el.style.animationDelay = `${i * 40}ms`;
        el.innerHTML = `
            <span class="prediction-rank">${i + 1}</span>
            <span class="prediction-name">${tech.name} <small style="color:var(--text-muted)">(${tech.techniqueId})</small></span>
            <span class="prediction-prob">${Math.round(tech.confidence * 100)}%</span>
            <span class="prediction-tactic">${tech.sources.join(', ')}</span>
        `;
        DOM.mappedTechniquesList.appendChild(el);
    });
}

function updateBeliefUI(belief) {
    if (!belief) return;
    const types = ['script_kiddie', 'organized_crime', 'apt_state', 'insider_threat'];
    types.forEach((type, i) => {
        const el = $(`belief-${i}`);
        if (el && belief[type] !== undefined) {
            const pct = (belief[type] * 100).toFixed(1) + '%';
            el.style.width = pct;
            el.setAttribute('data-value', pct);
        }
    });
}

function renderLiveMetrics() {
    if (!liveSession) return;
    const m = liveSession.metrics;
    DOM.lmIOCs.textContent = m.totalIOCs;
    DOM.lmMalicious.textContent = m.maliciousIOCs;
    DOM.lmTechniques.textContent = m.techniquesObserved;
    DOM.lmThreat.textContent = m.highestThreat;
    DOM.lmThreat.className = `metric-value threat-${m.highestThreat}`.replace('metric-value ', 'metric-value ');
    DOM.lmScore.textContent = m.avgThreatScore;
}

function renderEnrichment(enrichment) {
    if (!enrichment) return;

    let html = '';
    const results = enrichment.results || {};
    const errors = enrichment.errors || {};

    // OTX
    if (results.otx) {
        const otx = results.otx;
        html += `<div class="enrichment-feed otx">
            <div class="enrichment-feed-header">
                <span class="enrichment-feed-name" style="color:var(--accent-blue)">AlienVault OTX</span>
                <span class="feed-tag otx">${otx.pulseCount} Pulses</span>
            </div>
            <div class="enrichment-feed-detail">
                ${otx.country ? `Country: ${otx.country}` : ''} ${otx.asn ? `| ASN: ${otx.asn}` : ''}<br>
                ${otx.attackIds.length > 0 ? `ATT&CK: ${otx.attackIds.join(', ')}` : 'No ATT&CK mappings'}
            </div>
        </div>`;
    } else if (errors.otx) {
        html += `<div class="enrichment-feed otx"><div class="enrichment-feed-detail" style="color:var(--accent-red)">OTX: ${errors.otx}</div></div>`;
    }

    // VirusTotal
    if (results.virustotal) {
        const vt = results.virustotal;
        html += `<div class="enrichment-feed vt">
            <div class="enrichment-feed-header">
                <span class="enrichment-feed-name" style="color:var(--accent-purple)">VirusTotal</span>
                <span class="threat-badge ${vt.malicious >= 5 ? 'threat-HIGH' : vt.malicious >= 1 ? 'threat-MEDIUM' : 'threat-LOW'}">${vt.malicious}/${vt.malicious + vt.harmless + vt.undetected} Mal</span>
            </div>
            <div class="enrichment-feed-detail">
                Malicious: ${vt.malicious} | Suspicious: ${vt.suspicious}<br>
                ${vt.country ? `Country: ${vt.country}` : ''} ${vt.asOwner ? `| ${vt.asOwner}` : ''}<br>
                ${vt.mitreAttack?.length > 0 ? `ATT&CK: ${vt.mitreAttack.map(t => t.id).join(', ')}` : ''}
            </div>
        </div>`;
    } else if (errors.virustotal) {
        html += `<div class="enrichment-feed vt"><div class="enrichment-feed-detail" style="color:var(--accent-red)">VT: ${errors.virustotal}</div></div>`;
    }

    // AbuseIPDB
    if (results.abuseipdb) {
        const ab = results.abuseipdb;
        html += `<div class="enrichment-feed abuse">
            <div class="enrichment-feed-header">
                <span class="enrichment-feed-name" style="color:var(--accent-red)">AbuseIPDB</span>
                <span class="threat-badge ${ab.abuseConfidenceScore >= 80 ? 'threat-CRITICAL' : ab.abuseConfidenceScore >= 40 ? 'threat-MEDIUM' : 'threat-LOW'}">${ab.abuseConfidenceScore}%</span>
            </div>
            <div class="enrichment-feed-detail">
                Reports: ${ab.totalReports} from ${ab.numDistinctUsers} users<br>
                ${ab.isp ? `ISP: ${ab.isp}` : ''} ${ab.country ? `| ${ab.country}` : ''}<br>
                ${ab.categories.length > 0 ? `Categories: ${ab.categories.join(', ')}` : ''}
            </div>
        </div>`;
    } else if (errors.abuseipdb) {
        html += `<div class="enrichment-feed abuse"><div class="enrichment-feed-detail" style="color:var(--accent-red)">AbuseIPDB: ${errors.abuseipdb}</div></div>`;
    }

    if (!html) {
        html = '<div class="empty-state"><div class="icon">📡</div><p>No enrichment data received</p></div>';
    }

    DOM.enrichmentContent.innerHTML = html;
}

function renderLivePredictions(predictions) {
    // Reuse the shared predictions panel
    DOM.predictionsList.innerHTML = '';
    DOM.predictionsPanel.style.display = '';

    predictions.forEach((pred, i) => {
        const el = document.createElement('div');
        el.className = 'prediction-item animate-in';
        el.style.animationDelay = `${i * 50}ms`;
        el.innerHTML = `
            <span class="prediction-rank">${i + 1}</span>
            <span class="prediction-name">${pred.name} <small style="color:var(--text-muted)">(${pred.id})</small></span>
            <span class="prediction-prob">${(pred.probability * 100).toFixed(1)}%</span>
            <span class="prediction-tactic">${pred.tacticName || ''}</span>
        `;
        DOM.predictionsList.appendChild(el);
    });
}

function renderLiveActions(actions) {
    DOM.actionsList.innerHTML = '';
    DOM.actionsPanel.style.display = '';

    // Render Global Multi-Agent Action if present (threat-cluster overlap)
    if (liveSession && liveSession.globalMultiAgentStrategy) {
        const globalObj = liveSession.globalMultiAgentStrategy;
        const globalEl = document.createElement('div');
        globalEl.className = 'action-item global-action animate-in';
        globalEl.style.border = '1px solid var(--accent-purple)';
        globalEl.style.background = 'rgba(157, 78, 221, 0.1)';
        const euClass = globalObj.globalUtility >= 0 ? 'positive' : 'negative';
        globalEl.innerHTML = `
            <span class="action-eu ${euClass}">${globalObj.globalUtility >= 0 ? '+' : ''}${globalObj.globalUtility.toFixed(1)}</span>
            <span class="action-name" style="color:var(--accent-purple);font-weight:600;">[MULTI-THREAT GLOBAL] ${globalObj.bestGlobalAction}</span>
            <span class="action-meta">Optimal payout factoring ${globalObj.activeThreatsCount} concurrent threat clusters</span>
        `;
        DOM.actionsList.appendChild(globalEl);
    }

    actions.forEach((action, i) => {
        const el = document.createElement('div');
        el.className = 'action-item animate-in';
        el.style.animationDelay = `${i * 50}ms`;
        const euClass = action.expectedUtility >= 0 ? 'positive' : 'negative';
        el.innerHTML = `
            <span class="action-eu ${euClass}">${action.expectedUtility >= 0 ? '+' : ''}${action.expectedUtility.toFixed(1)}</span>
            <span class="action-name">${action.name}</span>
            <span class="action-meta">Cost: ${(action.cost * 100).toFixed(0)}% · Disr: ${(action.disruption * 100).toFixed(0)}%</span>
        `;
        DOM.actionsList.appendChild(el);
    });
}

function updateLiveKillChain(coverage) {
    // Kill chain stages are rendered in mapped techniques panel
}

// ═══════════════════════════════════════════════════════════════════════════
//  RL TRAINING FROM IOC REPLAY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Fetch experience count and update the RL panel display
 */
async function refreshRLExpCount() {
    try {
        const resp = await fetch('/api/ioc/rl-experiences?limit=1');
        const data = await resp.json();
        if (DOM.rlExpCount) {
            // Get actual count from a stats call
            const statsResp = await fetch('/api/history/summary');
            const summary = await statsResp.json();
            DOM.rlExpCount.textContent = summary.rlExperiences || 0;
        }
    } catch (e) {
        if (DOM.rlExpCount) DOM.rlExpCount.textContent = '?';
    }
}

/**
 * Run RL training from stored IOC experiences
 * @param {'ql'|'dqn'} agentType - Which agent to train
 */
async function runRLTraining(agentType) {
    if (isRunning) return;
    isRunning = true;

    const btnQL = DOM.btnTrainQL;
    const btnDQN = DOM.btnTrainDQN;
    const outputEl = DOM.rlTrainOutput;
    if (btnQL) btnQL.disabled = true;
    if (btnDQN) btnDQN.disabled = true;

    const agentLabel = agentType === 'dqn' ? 'DQN' : 'Q-Learning';
    if (outputEl) outputEl.innerHTML = `<div class="rl-train-status">⏳ Fetching experiences for ${agentLabel}…</div>`;

    try {
        // 1. Fetch stored experiences
        const resp = await fetch('/api/ioc/rl-replay', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ limit: 1000 })
        });
        const data = await resp.json();

        if (!data.success || !data.experiences || data.experiences.length === 0) {
            if (outputEl) outputEl.innerHTML = `<div class="rl-train-status" style="color:var(--accent-amber);">⚠ No experiences stored. Analyze IOCs first to generate training data.</div>`;
            isRunning = false;
            if (btnQL) btnQL.disabled = false;
            if (btnDQN) btnDQN.disabled = false;
            return;
        }

        const exps = data.experiences;
        if (outputEl) outputEl.innerHTML = `<div class="rl-train-status">🧠 Training ${agentLabel} on ${exps.length} experiences…</div>`;

        // Small delay to let UI update
        await delay(50);

        // 2. Run training
        let result;
        if (agentType === 'dqn') {
            result = trainFromIOCReplay(dqnAgent, exps, 3);
        } else {
            result = trainFromReplayBatch(rlAgent, exps, 5);
        }

        // 3. Persist Q-table
        if (agentType === 'ql') {
            try {
                await fetch('/api/rl/q-table', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(exportQTable(rlAgent))
                });
            } catch (e) { console.warn('Q-table persistence failed:', e); }
        }

        // 4. Render results
        const stats = agentType === 'dqn' ? getDQNAgentStats(dqnAgent) : getAgentStats(rlAgent);
        renderRLTrainingResults(agentType, result, stats);

        // Toast notification
        showInfo(`${agentLabel} trained: ${result.updatesApplied} updates from ${exps.length} experiences`);

    } catch (e) {
        if (outputEl) outputEl.innerHTML = `<div class="rl-train-status" style="color:var(--accent-red);">❌ Training failed: ${e.message}</div>`;
        showError('RL training failed: ' + e.message);
    }

    isRunning = false;
    if (btnQL) btnQL.disabled = false;
    if (btnDQN) btnDQN.disabled = false;
}

/**
 * Render training results in the RL panel
 */
function renderRLTrainingResults(agentType, result, stats) {
    const outputEl = DOM.rlTrainOutput;
    if (!outputEl) return;

    const label = agentType === 'dqn' ? 'DQN' : 'Q-Learning';
    const lossLine = agentType === 'dqn' ? `<div class="rl-stat"><span class="rl-stat-label">Avg Loss</span><span class="rl-stat-value">${result.avgLoss}</span></div>` : '';

    outputEl.innerHTML = `
        <div class="rl-train-status" style="color:var(--accent-green);">✅ ${label} training complete</div>
        <div class="rl-stats-mini">
            <div class="rl-stat"><span class="rl-stat-label">Updates</span><span class="rl-stat-value">${result.updatesApplied}</span></div>
            <div class="rl-stat"><span class="rl-stat-label">Avg Reward</span><span class="rl-stat-value">${result.avgReward ?? '—'}</span></div>
            ${lossLine}
            <div class="rl-stat"><span class="rl-stat-label">Episodes</span><span class="rl-stat-value">${stats.episodes}</span></div>
            <div class="rl-stat"><span class="rl-stat-label">ε (Explore)</span><span class="rl-stat-value">${stats.currentEpsilon.toFixed(3)}</span></div>
            <div class="rl-stat"><span class="rl-stat-label">${agentType === 'dqn' ? 'Buffer' : 'Q-States'}</span><span class="rl-stat-value">${stats.qTableStates}</span></div>
        </div>
    `;
}

/**
 * Load saved RL state from server on startup
 */
async function loadSavedRLState() {
    try {
        const resp = await fetch('/api/rl/q-table');
        if (resp.ok) {
            const data = await resp.json();
            importQTable(rlAgent, data);
            console.log(`Loaded Q-table: ${Object.keys(rlAgent.qTable).length} states`);
        }
    } catch (e) {
        // No saved Q-table, that's fine
    }
    refreshRLExpCount();
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function abbreviate(str, maxLen = 10) { return str.length <= maxLen ? str : str.substring(0, maxLen - 1) + '…'; }
function formatTypeName(type) {
    return { 'script_kiddie': 'Script Kid', 'organized_crime': 'Org. Crime', 'apt_state': 'APT/State', 'insider_threat': 'Insider' }[type] || type;
}

// ─── Boot ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);

// ─── Toast Notification System ────────────────────────────────────────────
const _toastContainer = () => document.getElementById('toast-container');

/**
 * Show a dismissible toast notification
 * @param {string} message - Message to display
 * @param {'error'|'info'|'warn'} type - Visual style (default 'error')
 * @param {number} duration - Auto-dismiss ms (default 5000)
 */
export function showError(message, type = 'error', duration = 5000) {
    const container = _toastContainer();
    if (!container) { console.error('[Toast]', message); return; }

    const icons = { error: '⚠️', info: 'ℹ️', warn: '🔔' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || '⚠️'}</span>
        <span class="toast-content">${message}</span>
    `;

    container.appendChild(toast);

    // Auto-dismiss after duration
    const dismiss = () => {
        toast.classList.add('hiding');
        toast.addEventListener('animationend', () => toast.remove(), { once: true });
    };
    setTimeout(dismiss, duration);
    toast.addEventListener('click', dismiss);
}

export function showInfo(message) {
    showError(message, 'info', 4000);
}
