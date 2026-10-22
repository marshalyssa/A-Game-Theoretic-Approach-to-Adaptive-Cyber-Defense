const fetch = require('node-fetch');

async function testOTX() {
    const ioc = '8.8.8.8';
    const type = 'IPv4';

    console.log(`Testing OTX lookup for ${ioc}... (Expected timeout: 15s, Max attempts: 3)`);
    const startTime = Date.now();

    try {
        const resp = await fetch('http://localhost:3000/api/cti/otx', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ioc, type })
        });

        const duration = (Date.now() - startTime) / 1000;
        const data = await resp.json();

        if (resp.ok) {
            console.log(`✅ OTX Success in ${duration.toFixed(1)}s`);
            console.log('Pulses found:', data.general?.pulse_info?.count || 0);
        } else {
            console.error(`❌ OTX Failed in ${duration.toFixed(1)}s:`, data.error || data);
        }
    } catch (err) {
        const duration = (Date.now() - startTime) / 1000;
        console.error(`❌ Request failed in ${duration.toFixed(1)}s:`, err.message);
    }
}

testOTX();
