const fs = require('fs');

let content = fs.readFileSync('js/app.js', 'utf8');

// Remove simulation imports
content = content.replace(/import \{ createSimConfig[^}]+\} from '\.\/engine\/simulation\.js';\n/, '');

// Remove global simulation state
content = content.replace(/let simState = null;\n/, '');
content = content.replace(/let autoPlayTimer = null;\n/, '');
content = content.replace(/let currentMode = 'simulation'; \/\/ 'simulation' \| 'live'/, "let currentMode = 'live'; // 'live'");

// Remove DOM properties for sim
content = content.replace(/\s*tabSim: \$\('tab-sim'\),/g, '');
content = content.replace(/\s*attackerType: \$\('attacker-type'\),/g, '');
content = content.replace(/\s*detectionCoverage: \$\('detection-coverage'\),.*?statusBadge: \$\('status-badge'\),/gs, '');

content = content.replace(/const SIM_PANELS = \[.*?\];/s, 'const SIM_PANELS = [];');

// Remove initialization for DOM bindings
content = content.replace(/DOM\.detectionCoverage\.addEventListener.*?DOM\.btnTrain\.addEventListener\('click', trainAgent\);/gs, '');

// Clean switchTab
content = content.replace(/DOM\.tabSim\.classList.*?DOM\.tabLive/s, 'DOM.tabLive');
content = content.replace(/DOM\.tabSim\.addEventListener\('click', \(\) => switchTab\('simulation'\)\);\n/s, '');

// Modify init default
content = content.replace(/switchTab\('simulation'\);/g, "switchTab('live');");

fs.writeFileSync('js/app.js', content, 'utf8');
console.log('Stripped basic sim config from app.js');
