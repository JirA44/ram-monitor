#!/usr/bin/env node
/**
 * RAM Monitor Launcher with Auto-Update
 * Downloads updates from GitHub on startup, then launches the server
 */

const { execSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const REPO_DIR = __dirname;
const REPO_URL = 'https://github.com/JirA44/ram-monitor.git';
const VERSION_FILE = path.join(REPO_DIR, 'version.json');

console.log(`
╔══════════════════════════════════════════╗
║     RAM Monitor + Security Watcher       ║
║              Launcher v1.0               ║
╚══════════════════════════════════════════╝
`);

async function checkForUpdates() {
    console.log('[Launcher] Checking for updates...');

    try {
        // Check if .git exists
        if (!fs.existsSync(path.join(REPO_DIR, '.git'))) {
            console.log('[Launcher] No .git folder, cloning fresh...');
            // This shouldn't happen if installed via git clone
            return false;
        }

        // Fetch
        console.log('[Launcher] Fetching from GitHub...');
        execSync('git fetch origin master', { cwd: REPO_DIR, stdio: 'pipe', timeout: 30000 });

        // Check local vs remote
        const localHash = execSync('git rev-parse HEAD', { cwd: REPO_DIR, encoding: 'utf8' }).trim();
        const remoteHash = execSync('git rev-parse origin/master', { cwd: REPO_DIR, encoding: 'utf8' }).trim();

        if (localHash !== remoteHash) {
            console.log('[Launcher] New version available!');
            console.log(`  Local:  ${localHash.substring(0, 7)}`);
            console.log(`  Remote: ${remoteHash.substring(0, 7)}`);
            console.log('[Launcher] Downloading update...');

            // Reset to remote (discard local changes)
            execSync('git reset --hard origin/master', { cwd: REPO_DIR, stdio: 'inherit' });

            // Check if dependencies changed
            const diff = execSync('git diff HEAD~1 --name-only 2>/dev/null || echo ""', { cwd: REPO_DIR, encoding: 'utf8' });
            if (diff.includes('package.json') || diff.includes('package-lock.json')) {
                console.log('[Launcher] Dependencies changed, installing...');
                execSync('npm install --production', { cwd: REPO_DIR, stdio: 'inherit', timeout: 120000 });
            }

            console.log('[Launcher] Update complete!');
            return true;
        } else {
            console.log('[Launcher] Already up to date');
            return false;
        }
    } catch (err) {
        console.log('[Launcher] Update check failed:', err.message);
        console.log('[Launcher] Continuing with current version...');
        return false;
    }
}

async function startServer() {
    console.log('[Launcher] Starting RAM Monitor server...\n');

    const server = spawn('node', ['server.js'], {
        cwd: REPO_DIR,
        stdio: 'inherit',
        shell: true
    });

    server.on('error', (err) => {
        console.error('[Launcher] Failed to start server:', err.message);
        process.exit(1);
    });

    server.on('exit', (code) => {
        console.log(`[Launcher] Server exited with code ${code}`);
        process.exit(code);
    });

    // Handle SIGINT
    process.on('SIGINT', () => {
        console.log('\n[Launcher] Shutting down...');
        server.kill('SIGINT');
    });
}

async function main() {
    await checkForUpdates();
    await startServer();
}

main().catch(console.error);
