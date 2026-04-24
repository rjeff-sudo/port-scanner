// This is the brain of your scanner. Use this to get the data, 
// then write your own CSS to display it.
async function executeScan(targetIP, portRange, workerCount) {
    const payload = {
        target: targetIP,
        ports: portRange,
        workers: parseInt(workerCount)
    };

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) throw new Error('Scan failed at server level');
        
        const data = await response.ok ? await response.json() : null;
        return data.report; // This returns the raw Go struct data
    } catch (err) {
        console.error("Scanner Error:", err);
        return null;
    }
}
