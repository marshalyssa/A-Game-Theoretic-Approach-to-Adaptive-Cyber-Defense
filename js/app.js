/**
 * App Controller — UI Wiring, Rendering, and Simulation Control
 * 
 * Two modes:
 *   1. Simulation — Run synthetic adversarial games with configurable attacker types
 *   2. Live IOC — Submit real IOCs, query CTI feeds, map to ATT&CK, predict next steps
 */

import { TACTICS, TECHNIQUE_BY_ID, TACTIC_PHASES } from './data/mitre-catalog.js';
import { ATTACKER_PROFILES, ATTACKER_TYPES } from './data/attacker-profiles.js';
import { DEFENDER_ACTIONS, DEFENDER_ACTION_IDS } from './data/defender-actions.js';
import { createBeliefState, getBeliefEntropy, getMaxEntropy } from './engine/bayesian-engine.js';
import { computePayoffMatrix, solveMixedStrategy } from './engine/game-engine.js';
import { createAgent, getAgentStats, resetAgent } from './engine/rl-agent.js';
import { createSimConfig, initSimulation, stepSimulation, runEpisode, runTraining, exportSimulationReport } from './engine/simulation.js';

// ─── Global State ──────────────────────────────────────────────────────────
let simState = null;
let rlAgent = createAgent();
let isRunning = false;
let autoPlayTimer = null;
let currentMode = 'simulation'; // 'simulation' | 'live'
let liveSession = null;

// ─── DOM References ────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const DOM = {
    // Tabs
    tabSim: $('tab-sim'),
    tabLive: $('tab-live'),
    // Sim config
    attackerType: $('attacker-type'),
    detectionCoverage: $('detection-coverage'),
    detectionVal: $('detection-val'),
    assetCriticality: $('asset-criticality'),
    maxSteps: $('max-steps'),
    useRL: $('use-rl'),
    useGT: $('use-gt'),
    btnRun: $('btn-run'),
    btnStep: $('btn-step'),
    btnReset: $('btn-reset'),
    btnTrain: $('btn-train'),
    statusBadge: $('status-badge'),
    entropyBadge: $('entropy-badge'),
    tacticBadge: $('tactic-badge'),
    stepBadge: $('step-badge'),
    beliefBars: $('belief-bars'),
    simLog: $('sim-log'),
    killChain: $('kill-chain'),
    predictionsList: $('predictions-list'),
    actionsList: $('actions-list'),
    traceBody: $('trace-body'),
    trainingChart: $('training-chart'),
    heatmapContainer: $('heatmap-container'),
    // Sim metrics
    mDetect: $('m-detect'),
    mPrevent: $('m-prevent'),
    mCost: $('m-cost'),
    mUtility: $('m-utility'),
    mAtkUtility: $('m-atk-utility'),
    mTTD: $('m-ttd'),
    // Training stats
    tsEpisodes: $('ts-episodes'),
    tsEpsilon: $('ts-epsilon'),
    tsReward: $('ts-reward'),
    // Panels
    configPanel: $('config-panel'),
    logPanel: $('log-panel'),
    metricsRow: $('metrics-row'),
    killchainPanel: $('killchain-panel'),
    predictionsPanel: $('predictions-panel'),
    actionsPanel: $('actions-panel'),
    tracePanel: $('trace-panel'),
    trainingPanel: $('training-panel'),
    heatmapPanel: $('heatmap-panel'),
    // IOC panels
    iocPanel: $('ioc-panel'),
    iocInput: $('ioc-input'),
    feedOTX: $('feed-otx'),
    feedVT: $('feed-vt'),
    feedAbuse: $('feed-abuse'),
    btnAnalyze: $('btn-analyze'),
    btnClearIOC: $('btn-clear-ioc'),
    feedStatusBadge: $('feed-status-badge'),
    enrichmentPanel: $('enrichment-panel'),
    enrichmentContent: $('enrichment-content'),
    liveMetricsRow: $('live-metrics-row'),
    lmIOCs: $('lm-iocs'),
    lmMalicious: $('lm-malicious'),
    lmTechniques: $('lm-techniques'),
    lmThreat: $('lm-threat'),
    lmScore: $('lm-score'),
    iocTimelinePanel: $('ioc-timeline-panel'),
    iocTimelineBody: $('ioc-timeline-body'),
    iocCountBadge: $('ioc-count-badge'),
    mappedTechniquesPanel: $('mapped-techniques-panel'),
    mappedTechniquesList: $('mapped-techniques-list'),
};

// Sim-only panels
const SIM_PANELS = ['config-panel', 'log-panel', 'metrics-row', 'predictions-panel', 'actions-panel', 'trace-panel', 'training-panel', 'heatmap-panel'];
// Live-only panels
const LIVE_PANELS = ['ioc-panel', 'enrichment-panel', 'live-metrics-row', 'ioc-timeline-panel', 'mapped-techniques-panel'];
// Shared panels
const SHARED_PANELS = ['killchain-panel', 'belief-panel'];

// ─── Initialize ────────────────────────────────────────────────────────────
function init() {
    buildKillChain();
    bindEvents();
    updateBeliefUI(createBeliefState());
    setStatus('idle', 'IDLE');
    log('System initialized. Configure parameters and click Run or Step.', '');
    switchTab('simulation'); // Default to simulation mode
}

// ─── Tab Switching ─────────────────────────────────────────────────────────
function switchTab(mode) {
    currentMode = mode;

    // Update tab buttons
    DOM.tabSim.classList.toggle('active', mode === 'simulation');
    DOM.tabLive.classList.toggle('active', mode === 'live');

    // Show/hide panels
    for (const id of SIM_PANELS) {
        const el = document.getElementById(id);
        if (el) el.style.display = mode === 'simulation' ? '' : 'none';
    }
    for (const id of LIVE_PANELS) {
        const el = document.getElementById(id);
        if (el) el.style.display = mode === 'live' ? '' : 'none';
    }

    // If switching to live mode, check feed status
    if (mode === 'live') {
        checkFeeds();
        if (!liveSession) {
            initLiveSession();
        }
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

// ─── Kill Chain Builder ────────────────────────────────────────────────────
function buildKillChain() {
    DOM.killChain.innerHTML = '';
    for (const tactic of TACTICS) {
        const el = document.createElement('div');
        el.className = 'kill-chain-stage';
        el.dataset.tacticId = tactic.id;
        el.dataset.phase = tactic.phase;
        el.textContent = tactic.name;
        el.title = tactic.description;
        DOM.killChain.appendChild(el);
    }
}

// ─── Event Binding ─────────────────────────────────────────────────────────
function bindEvents() {
    DOM.detectionCoverage.addEventListener('input', () => {
        DOM.detectionVal.textContent = DOM.detectionCoverage.value;
    });

    // Tab switching
    DOM.tabSim.addEventListener('click', () => switchTab('simulation'));
    DOM.tabLive.addEventListener('click', () => switchTab('live'));

    // Simulation controls
    DOM.btnRun.addEventListener('click', runFullSimulation);
    DOM.btnStep.addEventListener('click', stepOnce);
    DOM.btnReset.addEventListener('click', resetSimulation);
    DOM.btnTrain.addEventListener('click', trainAgent);

    // IOC controls
    DOM.btnAnalyze.addEventListener('click', runIOCAnalysis);
    DOM.btnClearIOC.addEventListener('click', clearLiveSession);
}

// ─── Get Config from UI ────────────────────────────────────────────────────
function getConfig() {
    return {
        attackerType: DOM.attackerType.value,
        detectionCoverage: parseInt(DOM.detectionCoverage.value) / 100,
        assetCriticality: parseInt(DOM.assetCriticality.value),
        maxSteps: parseInt(DOM.maxSteps.value) || 20,
        useRL: DOM.useRL.checked,
        useGameTheory: DOM.useGT.checked,
        noisyObservation: true,
        beliefDecayRate: 0.03,
    };
}

// ═══════════════════════════════════════════════════════════════════════════
//  SIMULATION MODE
// ═══════════════════════════════════════════════════════════════════════════

async function runFullSimulation() {
    if (isRunning) return;
    isRunning = true;
    setStatus('running', 'RUNNING');
    disableControls(true);

    const config = getConfig();
    simState = initSimulation(config);
    clearTrace();
    clearLog();
    resetKillChain();
    updateBeliefUI(simState.belief);

    log('▶ Simulation started', 'log-action');
    log(`  Attacker: ${ATTACKER_PROFILES[config.attackerType].name} (hidden)`, '');
    log(`  Detection: ${Math.round(config.detectionCoverage * 100)}% | Steps: ${config.maxSteps}`, '');

    const stepDelay = Math.max(80, 600 / config.maxSteps);
    while (!simState.gameOver) {
        await delay(stepDelay);
        const result = stepSimulation(simState, config.useRL ? rlAgent : null);
        if (result) renderStep(result);
    }

    if (simState.metrics) renderMetrics(simState.metrics);
    renderPayoffHeatmap(simState);
    log('■ Simulation complete', 'log-action');
    setStatus('idle', 'DONE');
    isRunning = false;
    disableControls(false);
}

function stepOnce() {
    if (isRunning) return;
    const config = getConfig();
    if (!simState || simState.gameOver) {
        simState = initSimulation(config);
        clearTrace(); clearLog(); resetKillChain();
        updateBeliefUI(simState.belief);
        log('▶ Simulation initialized (step mode)', 'log-action');
        setStatus('running', 'STEPPING');
    }
    const result = stepSimulation(simState, config.useRL ? rlAgent : null);
    if (result) renderStep(result);
    if (simState.gameOver && simState.metrics) {
        renderMetrics(simState.metrics);
        renderPayoffHeatmap(simState);
        log('■ Simulation complete', 'log-action');
        setStatus('idle', 'DONE');
    }
}

function resetSimulation() {
    if (autoPlayTimer) clearInterval(autoPlayTimer);
    simState = null; isRunning = false;
    clearTrace(); clearLog(); resetKillChain();
    updateBeliefUI(createBeliefState());
    resetMetrics();
    DOM.predictionsList.innerHTML = '<div class="empty-state"><div class="icon">🔮</div><p>Run simulation to see predictions</p></div>';
    DOM.actionsList.innerHTML = '<div class="empty-state"><div class="icon">⚔️</div><p>Run simulation to see recommendations</p></div>';
    DOM.heatmapContainer.innerHTML = '<div class="empty-state"><div class="icon">📊</div><p>Run simulation to see payoff matrix</p></div>';
    setStatus('idle', 'IDLE');
    disableControls(false);
    log('↺ Simulation reset', 'log-action');
}

async function trainAgent() {
    if (isRunning) return;
    isRunning = true;
    setStatus('running', 'TRAINING');
    disableControls(true);
    const config = getConfig();
    const numEpisodes = 100;
    log(`🧠 Training RL agent for ${numEpisodes} episodes…`, 'log-action');
    const batchSize = 5;
    for (let ep = 0; ep < numEpisodes; ep += batchSize) {
        await delay(10);
        const batchEnd = Math.min(ep + batchSize, numEpisodes);
        for (let i = ep; i < batchEnd; i++) {
            const state = runEpisode(config, rlAgent);
            const { recordEpisodeReward, decayEpsilon } = await import('./engine/rl-agent.js');
            recordEpisodeReward(rlAgent, state.cumulativeDefenderUtility);
            decayEpsilon(rlAgent);
        }
        const stats = getAgentStats(rlAgent);
        updateTrainingUI(stats);
        renderTrainingChart(stats.rewardHistory);
    }
    const stats = getAgentStats(rlAgent);
    log(`✓ Training complete: ${stats.episodes} episodes, avg reward: ${stats.avgReward}`, 'log-detect');
    log(`  Epsilon: ${stats.currentEpsilon}, Q-states: ${stats.qTableStates}`, '');
    setStatus('idle', 'TRAINED');
    isRunning = false;
    disableControls(false);
}

// ═══════════════════════════════════════════════════════════════════════════
//  LIVE IOC MODE
// ═══════════════════════════════════════════════════════════════════════════

async function runIOCAnalysis() {
    if (isRunning) return;

    const inputText = DOM.iocInput.value.trim();
    if (!inputText) return;

    isRunning = true;
    DOM.btnAnalyze.disabled = true;
    setStatus('running', 'ANALYZING');

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
            setStatus('idle', 'IDLE');
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

        setStatus('idle', 'DONE');
    } catch (e) {
        DOM.enrichmentContent.innerHTML = `
            <div class="empty-state" style="color: var(--accent-red);">
                <div class="icon">⚠️</div>
                <p>Error: ${e.message}</p>
                <p style="font-size: 0.72rem; margin-top: 4px; color: var(--text-muted);">Make sure the server is running (node server.js) and API keys are configured.</p>
            </div>
        `;
        setStatus('idle', 'ERROR');
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
    const stages = DOM.killChain.querySelectorAll('.kill-chain-stage');
    stages.forEach(stage => {
        const tacticId = stage.dataset.tacticId;
        if (coverage[tacticId] && coverage[tacticId].length > 0) {
            stage.classList.add('active');
            stage.title = `${stage.textContent}: ${coverage[tacticId].join(', ')}`;
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════
//  SHARED RENDERING
// ═══════════════════════════════════════════════════════════════════════════

function renderStep(step) {
    updateBeliefUI(step.belief);
    DOM.entropyBadge.textContent = `H = ${step.beliefEntropy.toFixed(2)}`;
    updateKillChain(step.tacticPhase, step.tacticId, step.detected);
    DOM.tacticBadge.textContent = `Phase: ${step.tacticName}`;
    DOM.stepBadge.textContent = `Step: ${step.timestep + 1}`;
    if (step.predictions?.length > 0) renderPredictions(step.predictions);
    if (step.gameAnalysis?.rankedActions) renderActions(step.gameAnalysis.rankedActions);
    addTraceRow(step);

    const detectClass = step.detected ? 'log-detect' : 'log-miss';
    const detectText = step.detected ? '✓ DETECTED' : '✗ MISSED';
    log(`[T${step.timestep}] ${step.technique.name} → ${detectText}`, detectClass);
    if (step.defenderAction) {
        log(`  ↳ Action: ${step.defenderAction.name}${step.defenderAction.isExploration ? ' (explore)' : ''}`, 'log-action');
    }
    if (step.attackPrevented) log(`  ↳ Attack PREVENTED`, 'log-prevent');

    if (simState) {
        const steps = simState.history.length;
        const detections = simState.history.filter(s => s.detected).length;
        const preventions = simState.history.filter(s => s.attackPrevented).length;
        DOM.mDetect.textContent = `${Math.round(detections / steps * 100)}%`;
        DOM.mPrevent.textContent = `${Math.round(preventions / steps * 100)}%`;
        DOM.mUtility.textContent = simState.cumulativeDefenderUtility.toFixed(1);
        DOM.mAtkUtility.textContent = simState.cumulativeAttackerUtility.toFixed(1);
    }
}

function updateBeliefUI(belief) {
    const types = ATTACKER_TYPES;
    const fills = DOM.beliefBars.querySelectorAll('.belief-bar-fill');
    for (let i = 0; i < types.length; i++) {
        const prob = belief[types[i]] || 0;
        const pct = Math.round(prob * 100);
        fills[i].style.width = `${Math.max(pct, 2)}%`;
        fills[i].setAttribute('data-value', `${pct}%`);
    }
    const entropy = getBeliefEntropy(belief);
    DOM.entropyBadge.textContent = `H = ${entropy.toFixed(2)}`;
}

function updateKillChain(currentPhase, currentTacticId, wasDetected) {
    const stages = DOM.killChain.querySelectorAll('.kill-chain-stage');
    stages.forEach(stage => {
        const phase = parseInt(stage.dataset.phase);
        if (phase < currentPhase) { stage.classList.add('visited'); stage.classList.remove('active'); }
        else if (phase === currentPhase) {
            stage.classList.add('active'); stage.classList.remove('visited');
            if (wasDetected) stage.classList.add('detected');
        }
    });
}

function resetKillChain() {
    DOM.killChain.querySelectorAll('.kill-chain-stage').forEach(s => {
        s.classList.remove('active', 'visited', 'detected');
    });
    DOM.tacticBadge.textContent = 'Phase: —';
}

function renderPredictions(predictions) {
    DOM.predictionsList.innerHTML = '';
    predictions.forEach((pred, i) => {
        const el = document.createElement('div');
        el.className = 'prediction-item animate-in';
        el.style.animationDelay = `${i * 50}ms`;
        el.innerHTML = `
            <span class="prediction-rank">${i + 1}</span>
            <span class="prediction-name">${pred.name} <small style="color:var(--text-muted)">(${pred.id})</small></span>
            <span class="prediction-prob">${(pred.probability * 100).toFixed(1)}%</span>
            <span class="prediction-tactic">${pred.tacticName}</span>
        `;
        DOM.predictionsList.appendChild(el);
    });
}

function renderActions(actions) {
    DOM.actionsList.innerHTML = '';
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

function addTraceRow(step) {
    const row = document.createElement('tr');
    row.className = 'animate-in';
    const detectClass = step.detected ? 'detected-yes' : 'detected-no';
    const preventClass = step.attackPrevented ? 'prevented' : 'not-prevented';
    const topBelief = step.mostProbableType;
    const actionLabel = step.defenderAction.isExploration ? `${step.defenderAction.name} 🎲` : step.defenderAction.name;
    row.innerHTML = `
        <td>${step.timestep}</td>
        <td>${step.tacticName}</td>
        <td title="${step.technique.id}">${step.technique.name}</td>
        <td class="${detectClass}">${step.detected ? '✓' : '✗'}</td>
        <td title="P=${(topBelief.probability * 100).toFixed(0)}%">${formatTypeName(topBelief.type)}</td>
        <td title="${step.defenderAction.id}">${actionLabel}</td>
        <td class="${preventClass}">${step.attackPrevented ? '✓' : '—'}</td>
        <td>${step.defenderUtility >= 0 ? '+' : ''}${step.defenderUtility.toFixed(1)}</td>
        <td>${step.attackerUtility >= 0 ? '+' : ''}${step.attackerUtility.toFixed(1)}</td>
        <td>${step.reward >= 0 ? '+' : ''}${step.reward.toFixed(1)}</td>
    `;
    DOM.traceBody.appendChild(row);
    const container = DOM.traceBody.closest('.trace-container');
    if (container) container.scrollTop = container.scrollHeight;
}

function clearTrace() { DOM.traceBody.innerHTML = ''; DOM.stepBadge.textContent = 'Step: 0'; }

function renderMetrics(metrics) {
    DOM.mDetect.textContent = `${Math.round(metrics.detectionRate * 100)}%`;
    DOM.mPrevent.textContent = `${Math.round(metrics.preventionRate * 100)}%`;
    DOM.mCost.textContent = metrics.totalCost.toFixed(1);
    DOM.mUtility.textContent = metrics.cumulativeDefenderUtility.toFixed(1);
    DOM.mAtkUtility.textContent = metrics.cumulativeAttackerUtility.toFixed(1);
    DOM.mTTD.textContent = metrics.timeToDetection >= 0 ? `T${metrics.timeToDetection}` : 'N/A';
}

function resetMetrics() {
    DOM.mDetect.textContent = '—'; DOM.mPrevent.textContent = '—'; DOM.mCost.textContent = '—';
    DOM.mUtility.textContent = '—'; DOM.mAtkUtility.textContent = '—'; DOM.mTTD.textContent = '—';
}

function updateTrainingUI(stats) {
    DOM.tsEpisodes.textContent = stats.episodes;
    DOM.tsEpsilon.textContent = stats.currentEpsilon.toFixed(3);
    DOM.tsReward.textContent = stats.recentAvgReward.toFixed(1);
}

function renderTrainingChart(rewardHistory) {
    const canvas = DOM.trainingChart;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr; canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const w = rect.width, h = rect.height;
    const padding = { top: 20, right: 20, bottom: 30, left: 50 };
    const plotW = w - padding.left - padding.right;
    const plotH = h - padding.top - padding.bottom;
    ctx.clearRect(0, 0, w, h);
    if (rewardHistory.length < 2) return;
    const windowSize = Math.min(10, Math.floor(rewardHistory.length / 3) || 1);
    const smoothed = [];
    for (let i = 0; i < rewardHistory.length; i++) {
        const start = Math.max(0, i - windowSize + 1);
        const slice = rewardHistory.slice(start, i + 1);
        smoothed.push(slice.reduce((s, v) => s + v, 0) / slice.length);
    }
    const minR = Math.min(...rewardHistory), maxR = Math.max(...rewardHistory);
    const range = maxR - minR || 1;
    const toX = i => padding.left + (i / (rewardHistory.length - 1)) * plotW;
    const toY = v => padding.top + plotH - ((v - minR) / range) * plotH;
    ctx.strokeStyle = 'rgba(255,255,255,0.06)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = padding.top + (plotH / 4) * i;
        ctx.beginPath(); ctx.moveTo(padding.left, y); ctx.lineTo(w - padding.right, y); ctx.stroke();
        const val = maxR - (range / 4) * i;
        ctx.fillStyle = 'rgba(255,255,255,0.3)'; ctx.font = '10px JetBrains Mono, monospace';
        ctx.textAlign = 'right'; ctx.fillText(val.toFixed(0), padding.left - 6, y + 3);
    }
    ctx.textAlign = 'center'; ctx.fillStyle = 'rgba(255,255,255,0.3)';
    for (const idx of [0, Math.floor(rewardHistory.length / 2), rewardHistory.length - 1]) {
        ctx.fillText(idx.toString(), toX(idx), h - 8);
    }
    ctx.fillStyle = 'rgba(56, 189, 248, 0.15)';
    for (let i = 0; i < rewardHistory.length; i++) {
        ctx.beginPath(); ctx.arc(toX(i), toY(rewardHistory[i]), 2, 0, Math.PI * 2); ctx.fill();
    }
    ctx.strokeStyle = '#38bdf8'; ctx.lineWidth = 2; ctx.beginPath();
    ctx.moveTo(toX(0), toY(smoothed[0]));
    for (let i = 1; i < smoothed.length; i++) ctx.lineTo(toX(i), toY(smoothed[i]));
    ctx.stroke();
    const gradient = ctx.createLinearGradient(0, padding.top, 0, h - padding.bottom);
    gradient.addColorStop(0, 'rgba(56, 189, 248, 0.15)'); gradient.addColorStop(1, 'rgba(56, 189, 248, 0.0)');
    ctx.fillStyle = gradient; ctx.beginPath();
    ctx.moveTo(toX(0), toY(smoothed[0]));
    for (let i = 1; i < smoothed.length; i++) ctx.lineTo(toX(i), toY(smoothed[i]));
    ctx.lineTo(toX(smoothed.length - 1), h - padding.bottom); ctx.lineTo(toX(0), h - padding.bottom);
    ctx.closePath(); ctx.fill();
    ctx.fillStyle = 'rgba(255,255,255,0.4)'; ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'center'; ctx.fillText('Episode', w / 2, h - 2);
    ctx.save(); ctx.translate(12, h / 2); ctx.rotate(-Math.PI / 2);
    ctx.fillText('Reward', 0, 0); ctx.restore();
}

function renderPayoffHeatmap(simState) {
    if (!simState || simState.history.length === 0) return;
    const usedTechIds = [...new Set(simState.attackerTechniques)].slice(0, 8);
    const actionIds = DEFENDER_ACTION_IDS.slice(0, 8);
    const payoff = computePayoffMatrix(usedTechIds, actionIds, simState.config.detectionCoverage);
    const allVals = payoff.defenderMatrix.flat();
    const minVal = Math.min(...allVals), maxVal = Math.max(...allVals);
    let html = '<table class="heatmap-table"><thead><tr><th class="row-header">Technique \\ Action</th>';
    for (const actId of actionIds) { html += `<th title="${DEFENDER_ACTIONS[actId]?.name || actId}">${abbreviate(DEFENDER_ACTIONS[actId]?.name || actId)}</th>`; }
    html += '</tr></thead><tbody>';
    for (let i = 0; i < usedTechIds.length; i++) {
        const tech = TECHNIQUE_BY_ID[usedTechIds[i]];
        const name = tech ? tech.name : usedTechIds[i];
        html += `<tr><th class="row-header" title="${name}">${abbreviate(name, 16)}</th>`;
        for (let j = 0; j < actionIds.length; j++) {
            const val = payoff.defenderMatrix[i][j];
            const color = heatmapColor(val, minVal, maxVal);
            html += `<td class="heatmap-cell" style="background:${color}" title="${name} vs ${DEFENDER_ACTIONS[actionIds[j]]?.name}: ${val.toFixed(1)}">${val.toFixed(1)}</td>`;
        }
        html += '</tr>';
    }
    html += '</tbody></table>';
    DOM.heatmapContainer.innerHTML = html;
}

function heatmapColor(val, min, max) {
    const range = max - min || 1;
    const t = (val - min) / range;
    if (t < 0.5) { return `rgba(220, ${Math.round(100 + t * 2 * 155)}, 60, 0.7)`; }
    else { return `rgba(${Math.round(220 - (t - 0.5) * 2 * 160)}, 200, ${Math.round(60 + (t - 0.5) * 2 * 80)}, 0.7)`; }
}

// ─── Logging ───────────────────────────────────────────────────────────────
function log(message, cssClass) {
    const entry = document.createElement('div');
    entry.className = `log-entry ${cssClass || ''}`;
    entry.textContent = message;
    DOM.simLog.appendChild(entry);
    DOM.simLog.scrollTop = DOM.simLog.scrollHeight;
    while (DOM.simLog.children.length > 100) DOM.simLog.removeChild(DOM.simLog.firstChild);
}

function clearLog() { DOM.simLog.innerHTML = ''; }

function setStatus(state, label) {
    const dot = DOM.statusBadge.querySelector('.status-dot') || document.createElement('span');
    dot.className = `status-dot ${state}`;
    DOM.statusBadge.innerHTML = '';
    DOM.statusBadge.appendChild(dot);
    DOM.statusBadge.appendChild(document.createTextNode(label));
}

function disableControls(disabled) {
    DOM.btnRun.disabled = disabled;
    DOM.btnStep.disabled = disabled;
    DOM.btnReset.disabled = disabled;
    DOM.btnTrain.disabled = disabled;
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function abbreviate(str, maxLen = 10) { return str.length <= maxLen ? str : str.substring(0, maxLen - 1) + '…'; }
function formatTypeName(type) {
    return { 'script_kiddie': 'Script Kid', 'organized_crime': 'Org. Crime', 'apt_state': 'APT/State', 'insider_threat': 'Insider' }[type] || type;
}

// ─── Boot ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
