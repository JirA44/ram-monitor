# RAM Monitor + Security Watcher

Dashboard web temps réel pour surveiller la RAM, CPU et détecter les processus suspects sous Windows.

![Dashboard Preview](https://img.shields.io/badge/Platform-Windows-blue) ![Node.js](https://img.shields.io/badge/Node.js-18+-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

## Fonctionnalités

- **RAM en temps réel** - Jauge visuelle + graphique historique
- **CPU monitoring** - Usage en temps réel
- **Détail navigateurs** - Brave, Chrome, Firefox, Edge avec RAM par navigateur
- **Top 20 processus** - Triés par consommation RAM
- **Détection suspects** - Processus inconnus, noms bizarres, chemins temp
- **Alertes sécurité** - Notifications RAM critique et processus suspects
- **Kill process** - Terminer un processus directement depuis le dashboard
- **WebSocket** - Mise à jour temps réel (3 secondes)

## Installation

```bash
git clone https://github.com/VOTRE_USER/ram-monitor.git
cd ram-monitor
npm install
```

## Usage

```bash
# Démarrer
npm start

# Ou avec PM2 (recommandé)
pm2 start server.js --name ram-monitor
```

Ouvrir http://localhost:3333

## Configuration

Modifier dans `server.js`:

```javascript
const PORT = 3333;  // Port du serveur

// Ajouter des processus connus
const KNOWN_PROCESSES = new Set([
    'brave', 'chrome', 'firefox', ...
]);

// Patterns suspects personnalisés
const SUSPICIOUS_PATTERNS = [
    /miner/i, /crypto/i, ...
];
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML |
| `/api/stats` | GET | Données JSON complètes |
| `/api/kill/:pid` | POST | Terminer un processus |

## Screenshots

### Dashboard principal
- Jauges RAM/CPU avec couleurs dynamiques (vert/jaune/rouge)
- Graphiques historiques (60 points)
- Liste des navigateurs avec RAM détaillée

### Détection sécurité
- Processus marqués: ✅ Connu, ⚠️ Inconnu, 🚨 Suspect
- Raisons détaillées pour chaque alerte
- Bouton "Terminer" pour les suspects

## Technologies

- Node.js + Express
- WebSocket (ws)
- systeminformation
- HTML/CSS/JS vanilla (pas de framework)

## License

MIT
