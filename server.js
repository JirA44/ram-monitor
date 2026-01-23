const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const si = require('systeminformation');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = 3333;

// Processus connus/safe
const KNOWN_PROCESSES = new Set([
    'system', 'svchost', 'csrss', 'wininit', 'services', 'lsass', 'winlogon',
    'explorer', 'dwm', 'taskhostw', 'sihost', 'ctfmon', 'conhost', 'dllhost',
    'runtimebroker', 'searchhost', 'startmenuexperiencehost', 'shellexperiencehost',
    'textinputhost', 'systemsettings', 'applicationframehost', 'fontdrvhost',
    'wmiprvse', 'spoolsv', 'msmpeng', 'securityhealthservice', 'nissrv',
    'brave', 'chrome', 'firefox', 'msedge', 'code', 'claude', 'node', 'pwsh',
    'powershell', 'cmd', 'windowsterminal', 'git', 'npm', 'python', 'python3',
    'pm2', 'ollama', 'stockfish', 'malwarebytes', 'mbamservice',
    'nvcontainer', 'nvdisplay.container', 'nvidia overlay',
    'phoneexperiencehost', 'sysinfocap', 'onedrive', 'teams', 'slack',
    'discord', 'spotify', 'steam', 'epicgameslauncher', 'searchindexer',
    'audiodg', 'gamebar', 'widgets', 'taskmgr', 'notepad', 'calc',
    'wrangler', 'cloudflared', 'registry', 'smartscreen', 'securityhealthsystray'
]);

// Patterns suspects
const SUSPICIOUS_PATTERNS = [
    /miner/i, /crypto/i, /xmr/i, /monero/i, /coinhive/i,
    /keylog/i, /stealer/i, /^rat\d*$/i, /trojan/i,
    /backdoor/i, /rootkit/i, /ransom/i, /malware/i,
    /^[a-z]{1,2}$/i, /^[0-9a-f]{16,}$/i
];

// Chemins suspects
const SUSPICIOUS_PATHS = [
    /\\temp\\/i, /\\tmp\\/i, /appdata\\local\\temp/i
];

let alerts = [];
let history = {
    ram: [],
    cpu: []
};

function isKnownProcess(name) {
    return KNOWN_PROCESSES.has(name.toLowerCase());
}

function checkSuspicious(proc) {
    const reasons = [];

    // Check name patterns
    for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(proc.name)) {
            reasons.push(`Nom suspect: ${proc.name}`);
            break;
        }
    }

    // Unknown + high resources
    if (!isKnownProcess(proc.name)) {
        if (proc.memRss > 500 * 1024 * 1024) { // >500MB
            reasons.push(`Inconnu + RAM elevee: ${Math.round(proc.memRss / 1024 / 1024)}MB`);
        }
        if (proc.cpu > 30) {
            reasons.push(`Inconnu + CPU eleve: ${proc.cpu.toFixed(1)}%`);
        }
    }

    // Check path
    if (proc.path) {
        for (const pattern of SUSPICIOUS_PATHS) {
            if (pattern.test(proc.path)) {
                reasons.push(`Chemin suspect: ${proc.path}`);
                break;
            }
        }
    }

    return reasons;
}

async function getSystemData() {
    try {
        const [mem, cpu, processes, osInfo, currentLoad] = await Promise.all([
            si.mem(),
            si.cpu(),
            si.processes(),
            si.osInfo(),
            si.currentLoad()
        ]);

        // Calculate RAM
        const ramUsed = mem.used;
        const ramTotal = mem.total;
        const ramPercent = (ramUsed / ramTotal * 100).toFixed(1);

        // CPU
        const cpuPercent = currentLoad.currentLoad.toFixed(1);

        // History (keep last 60 points = 5 min at 5s interval)
        history.ram.push({ time: Date.now(), value: parseFloat(ramPercent) });
        history.cpu.push({ time: Date.now(), value: parseFloat(cpuPercent) });
        if (history.ram.length > 60) history.ram.shift();
        if (history.cpu.length > 60) history.cpu.shift();

        // Process list with analysis
        const procList = processes.list
            .sort((a, b) => b.memRss - a.memRss)
            .slice(0, 30)
            .map(p => {
                const suspiciousReasons = checkSuspicious(p);
                return {
                    pid: p.pid,
                    name: p.name,
                    cpu: p.cpu.toFixed(1),
                    ramMB: Math.round(p.memRss / 1024 / 1024),
                    path: p.path || '',
                    isKnown: isKnownProcess(p.name),
                    isSuspicious: suspiciousReasons.length > 0,
                    suspiciousReasons: suspiciousReasons
                };
            });

        // Browsers
        const browserNames = ['brave', 'chrome', 'firefox', 'msedge', 'opera'];
        const browsers = {};
        let browserTotal = 0;

        for (const proc of processes.list) {
            const nameLower = proc.name.toLowerCase();
            for (const browser of browserNames) {
                if (nameLower.includes(browser)) {
                    if (!browsers[browser]) {
                        browsers[browser] = { count: 0, ramMB: 0 };
                    }
                    browsers[browser].count++;
                    browsers[browser].ramMB += Math.round(proc.memRss / 1024 / 1024);
                    browserTotal += proc.memRss;
                }
            }
        }

        // Suspicious processes
        const suspicious = procList.filter(p => p.isSuspicious);

        // Add alerts
        if (parseFloat(ramPercent) > 85) {
            const alert = { type: 'RAM', message: `RAM critique: ${ramPercent}%`, time: Date.now() };
            if (!alerts.find(a => a.message === alert.message && Date.now() - a.time < 60000)) {
                alerts.unshift(alert);
            }
        }

        for (const s of suspicious) {
            const alert = { type: 'SECURITY', message: `Suspect: ${s.name} - ${s.suspiciousReasons.join(', ')}`, time: Date.now() };
            if (!alerts.find(a => a.message === alert.message && Date.now() - a.time < 300000)) {
                alerts.unshift(alert);
            }
        }

        // Keep only last 20 alerts
        alerts = alerts.slice(0, 20);

        return {
            ram: {
                usedMB: Math.round(ramUsed / 1024 / 1024),
                totalMB: Math.round(ramTotal / 1024 / 1024),
                percent: parseFloat(ramPercent)
            },
            cpu: {
                percent: parseFloat(cpuPercent),
                model: cpu.brand,
                cores: cpu.cores
            },
            processes: procList,
            browsers: browsers,
            browserTotalMB: Math.round(browserTotal / 1024 / 1024),
            suspicious: suspicious,
            alerts: alerts,
            history: history,
            os: {
                platform: osInfo.platform,
                distro: osInfo.distro,
                release: osInfo.release
            }
        };
    } catch (err) {
        console.error('Error getting system data:', err);
        return { error: err.message };
    }
}

// Serve static dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// API endpoint
app.get('/api/stats', async (req, res) => {
    const data = await getSystemData();
    res.json(data);
});

// Kill process endpoint
app.post('/api/kill/:pid', (req, res) => {
    const pid = parseInt(req.params.pid);
    try {
        process.kill(pid, 'SIGTERM');
        res.json({ success: true, message: `Process ${pid} terminated` });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// WebSocket for real-time updates
wss.on('connection', (ws) => {
    console.log('Client connected');

    const interval = setInterval(async () => {
        const data = await getSystemData();
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(data));
        }
    }, 3000); // Update every 3 seconds

    ws.on('close', () => {
        console.log('Client disconnected');
        clearInterval(interval);
    });
});

server.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`   RAM Monitor Dashboard v1.0`);
    console.log(`========================================`);
    console.log(`\n   Dashboard: http://localhost:${PORT}`);
    console.log(`   API: http://localhost:${PORT}/api/stats`);
    console.log(`\n   Press Ctrl+C to stop\n`);
});
