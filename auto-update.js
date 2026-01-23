const { execSync } = require('child_process');
const path = require('path');

const REPO_DIR = __dirname;
const REPO_URL = 'https://github.com/JirA44/ram-monitor.git';

async function checkForUpdates() {
    console.log('\n[Auto-Update] Checking for updates...');

    try {
        // Check if git repo exists
        try {
            execSync('git status', { cwd: REPO_DIR, stdio: 'pipe' });
        } catch {
            console.log('[Auto-Update] Not a git repo, skipping update check');
            return false;
        }

        // Fetch latest
        console.log('[Auto-Update] Fetching from remote...');
        execSync('git fetch origin', { cwd: REPO_DIR, stdio: 'pipe' });

        // Check if behind
        const status = execSync('git status -uno', { cwd: REPO_DIR, encoding: 'utf8' });

        if (status.includes('behind')) {
            console.log('[Auto-Update] Updates available! Pulling...');

            // Stash local changes
            try {
                execSync('git stash', { cwd: REPO_DIR, stdio: 'pipe' });
            } catch {}

            // Pull
            execSync('git pull origin master', { cwd: REPO_DIR, stdio: 'inherit' });

            // Pop stash
            try {
                execSync('git stash pop', { cwd: REPO_DIR, stdio: 'pipe' });
            } catch {}

            // Check if package.json changed (need npm install)
            const diff = execSync('git diff HEAD~1 --name-only', { cwd: REPO_DIR, encoding: 'utf8' });
            if (diff.includes('package.json')) {
                console.log('[Auto-Update] package.json changed, running npm install...');
                execSync('npm install', { cwd: REPO_DIR, stdio: 'inherit' });
            }

            console.log('[Auto-Update] Update complete! Restarting...');
            return true;
        } else {
            console.log('[Auto-Update] Already up to date');
            return false;
        }
    } catch (err) {
        console.log('[Auto-Update] Error checking updates:', err.message);
        return false;
    }
}

module.exports = { checkForUpdates };

// Run standalone
if (require.main === module) {
    checkForUpdates().then(updated => {
        if (updated) {
            console.log('Updated! Please restart the application.');
            process.exit(0);
        }
    });
}
