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
const LEARNED_PATH = path.join(__dirname, 'learned_processes.json');

// Processus connus/safe (hardcodés)
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
    'wrangler', 'cloudflared', 'registry', 'smartscreen', 'securityhealthsystray',
    'bun', 'tailscaled', 'pythonw', 'kdrive', 'proton', 'protondrive',
    'adblock360svc', 'memory compression', 'searchapp', 'lockapp',
    'regsvc', 'lsaiso', 'fontdrvhost', 'microsoftedge', 'msedgewebview2',
    'sgrmbroker', 'wuauclt', 'wudfhost', 'msiexec', 'csc', 'vbcscompiler',
    'nvtelemetrycontainer', 'nvspcaps64', 'nvidia share', 'nvsphelper64',
    'opera', 'brave', 'vivaldi', 'waterfox', 'palemoon',
    'powertoys', 'everything', 'flow.launcher', 'keypirinha',
    'rtkaudioservice', 'rtkauduservice64', 'hkcmd', 'igfxtray',
    'googledrivesyncer', 'googledrivefs', 'dropbox', 'box',
    'windscribe', 'nordvpn', 'expressvpn', 'protonvpn',
    'lghub', 'ghub', 'razer', 'corsair', 'steelseries',
    'obs64', 'obs', 'streamlabs', 'xsplit',
    'putty', 'winscp', 'filezilla', 'cyberduck',
    'postman', 'insomnia', 'dbeaver', 'tableplus',
    'docker', 'dockerd', 'com.docker', 'wsl', 'wslhost',
    'idea64', 'webstorm64', 'pycharm64', 'clion64', 'rider64',
    'devenv', 'msbuild', 'dotnet'
]);

// Processus appris automatiquement au démarrage
let learnedProcesses = new Set();

function loadLearned() {
    try {
        if (fs.existsSync(LEARNED_PATH)) {
            const data = JSON.parse(fs.readFileSync(LEARNED_PATH, 'utf8'));
            learnedProcesses = new Set(data);
            console.log(`   Loaded ${learnedProcesses.size} learned processes`);
        }
    } catch (e) {
        console.error('Could not load learned processes:', e.message);
    }
}

function saveLearned() {
    fs.writeFileSync(LEARNED_PATH, JSON.stringify([...learnedProcesses], null, 2));
}

async function learnCurrentProcesses() {
    try {
        const procs = await si.processes();
        let newCount = 0;
        for (const p of procs.list) {
            const n = p.name.toLowerCase().replace(/\.exe$/, '');
            if (!learnedProcesses.has(n)) {
                learnedProcesses.add(n);
                newCount++;
            }
        }
        if (newCount > 0) {
            saveLearned();
            console.log(`   Auto-learned ${newCount} new processes (total: ${learnedProcesses.size})`);
        }
    } catch (e) {
        console.error('Could not learn processes:', e.message);
    }
}

// Patterns suspects
const SUSPICIOUS_PATTERNS = [
    /miner/i, /xmrig/i, /xmr/i, /monero/i, /coinhive/i,
    /keylog/i, /stealer/i, /^rat\d*$/i, /trojan/i,
    /backdoor/i, /rootkit/i, /ransom/i, /malware/i,
    /^[0-9a-f]{16,}$/i
];

// Chemins suspects
const SUSPICIOUS_PATHS = [
    /\\temp\\/i, /\\tmp\\/i, /appdata\\local\\temp/i
];

let alerts = [];
let history = { ram: [], cpu: [] };

function isKnownProcess(name) {
    const n = name.toLowerCase().replace(/\.exe$/, '');
    return KNOWN_PROCESSES.has(n) || learnedProcesses.has(n);
}

function addToWhitelist(name) {
    const n = name.toLowerCase().replace(/\.exe$/, '');
    learnedProcesses.add(n);
    saveLearned();
}

function checkSuspicious(proc) {
    const reasons = [];

    for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(proc.name)) {
            reasons.push(`Nom suspect: ${proc.name}`);
            break;
        }
    }

    // memRss is in KB — 500MB = 500*1024 KB
    if (!isKnownProcess(proc.name)) {
        if (proc.memRss > 500 * 1024) {
            reasons.push(`Inconnu + RAM elevee: ${Math.round(proc.memRss / 1024)}MB`);
        }
        if (proc.cpu > 30) {
            reasons.push(`Inconnu + CPU eleve: ${proc.cpu.toFixed(1)}%`);
        }
    }

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

        const ramUsed = mem.used;
        const ramTotal = mem.total;
        const ramPercent = (ramUsed / ramTotal * 100).toFixed(1);
        const cpuPercent = currentLoad.currentLoad.toFixed(1);

        history.ram.push({ time: Date.now(), value: parseFloat(ramPercent) });
        history.cpu.push({ time: Date.now(), value: parseFloat(cpuPercent) });
        if (history.ram.length > 60) history.ram.shift();
        if (history.cpu.length > 60) history.cpu.shift();

        const procList = processes.list
            .sort((a, b) => b.memRss - a.memRss)
            .slice(0, 30)
            .map(p => {
                const suspiciousReasons = checkSuspicious(p);
                return {
                    pid: p.pid,
                    name: p.name,
                    cpu: p.cpu.toFixed(1),
                    ramMB: Math.round(p.memRss / 1024),
                    path: p.path || '',
                    isKnown: isKnownProcess(p.name),
                    isSuspicious: suspiciousReasons.length > 0,
                    suspiciousReasons: suspiciousReasons
                };
            });

        const browserNames = ['brave', 'chrome', 'firefox', 'msedge', 'opera'];
        const browsers = {};
        let browserTotal = 0;

        for (const proc of processes.list) {
            const nameLower = proc.name.toLowerCase();
            for (const browser of browserNames) {
                if (nameLower.includes(browser)) {
                    if (!browsers[browser]) browsers[browser] = { count: 0, ramMB: 0 };
                    browsers[browser].count++;
                    browsers[browser].ramMB += Math.round(proc.memRss / 1024);
                    browserTotal += proc.memRss;
                }
            }
        }

        const suspicious = procList.filter(p => p.isSuspicious);

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
            browserTotalMB: Math.round(browserTotal / 1024),
            suspicious: suspicious,
            alerts: alerts,
            history: history,
            learnedCount: learnedProcesses.size,
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

app.use(express.json());

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/api/stats', async (req, res) => {
    const data = await getSystemData();
    res.json(data);
});

app.post('/api/kill/:pid', (req, res) => {
    const pid = parseInt(req.params.pid);
    try {
        process.kill(pid, 'SIGTERM');
        res.json({ success: true, message: `Process ${pid} terminated` });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// Ajouter manuellement un process à la whitelist
app.post('/api/whitelist/:name', (req, res) => {
    addToWhitelist(req.params.name);
    res.json({ success: true, message: `${req.params.name} ajouté à la whitelist` });
});

// Relancer l'apprentissage
app.post('/api/learn', async (req, res) => {
    await learnCurrentProcesses();
    res.json({ success: true, learned: learnedProcesses.size });
});

wss.on('connection', (ws) => {
    console.log('Client connected');
    const interval = setInterval(async () => {
        const data = await getSystemData();
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
    }, 3000);
    ws.on('close', () => { clearInterval(interval); });
});

// Init
loadLearned();
server.listen(PORT, async () => {
    console.log(`\n========================================`);
    console.log(`   RAM Monitor + Security Watcher`);
    console.log(`========================================`);
    console.log(`\n   Dashboard: http://localhost:${PORT}`);
    console.log(`   Whitelist: POST /api/whitelist/:name`);
    console.log(`   Re-learn:  POST /api/learn\n`);
    await learnCurrentProcesses();
});
