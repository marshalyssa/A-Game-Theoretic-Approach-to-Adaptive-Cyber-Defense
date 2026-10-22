const fetch = require('node-fetch');

const dummyReport = {
    config: {
        attackerType: 'apt_state',
        detectionCoverage: 0.5,
        useRL: true,
        useGameTheory: true
    },
    metrics: {
        logLoss: 0.45,
        top3HitRate: 0.8,
        detectionRate: 0.7,
        preventionRate: 0.3,
        totalSteps: 20
    },
    history: [
        {
            timestep: 0,
            tacticId: 'TA0001',
            technique: { id: 'T1566' },
            detected: true,
            defenderAction: { id: 'deploy_edr' },
            reward: 2.5
        }
    ]
};

async function testPersistence() {
    try {
        const resp = await fetch('http://localhost:3000/api/sim/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(dummyReport)
        });
        const data = await resp.json();
        console.log('Save result:', data);

        const listResp = await fetch('http://localhost:3000/api/sim/recent');
        const listData = await listResp.json();
        console.log('Recent sims:', listData);
    } catch (err) {
        console.error('Test failed:', err);
    }
}

testPersistence();
