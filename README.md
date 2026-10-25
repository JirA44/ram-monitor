# RAM Monitor + Security Watcher

Dashboard local pour observer l’usage de la mémoire et du processeur sous Windows, voir les processus les plus consommateurs et examiner des alertes basées sur des règles.

## À quoi sert-il ?

L’application fournit une vue d’ensemble des ressources du PC et des processus en cours dans un navigateur local. Elle peut aider à repérer une application gourmande en mémoire ou à investiguer un processus qui mérite une vérification.

## Pourquoi l’utiliser ?

Le Gestionnaire des tâches donne des informations utiles, mais un tableau de bord dédié peut afficher l’historique, détailler les navigateurs et regrouper des règles de surveillance. Cela facilite une première investigation quand le PC ralentit ou que la mémoire semble saturée.

Les étiquettes « inconnu » ou « suspect » sont des signaux fondés sur des règles simples, pas une preuve qu’un processus est malveillant. Les faux positifs sont possibles. Examiner le nom, l’emplacement et l’éditeur du programme avant toute action.

## Exemples d’utilisation

- **Comprendre un ralentissement** : ouvrir le dashboard, comparer les jauges RAM/CPU et repérer les processus qui consomment le plus.
- **Suivre une hausse de mémoire** : laisser le dashboard ouvert et observer l’évolution de l’historique pendant qu’une application est utilisée.
- **Vérifier une alerte** : lire la raison signalée, confirmer quel logiciel est concerné et rechercher sa provenance avant de décider quoi que ce soit.
- **Terminer un processus bloqué** : utiliser l’action de fermeture uniquement après avoir identifié le processus et enregistré les travaux ouverts.

Le dashboard ne remplace ni un antivirus ni une analyse de sécurité complète.

## Installation et démarrage

Prérequis : Node.js 18 ou supérieur.

```powershell
git clone https://github.com/JirA44/ram-monitor.git
cd ram-monitor
npm install
npm start
```

Ouvrir ensuite http://localhost:3333 dans le navigateur. Le serveur écoute localement selon la configuration du projet.

Pour démarrer le serveur avec PM2 :

```bash
pm2 start server.js --name ram-monitor
```

## Fonctions

- jauges RAM/CPU et graphique historique ;
- vue des principaux processus et de l’usage mémoire des navigateurs ;
- alertes basées sur des processus connus et des motifs configurables ;
- mise à jour en temps réel par WebSocket ;
- action de terminaison de processus, à utiliser après vérification.

## API locale

| Endpoint | Méthode | Usage |
| --- | --- | --- |
| `/` | GET | interface du dashboard |
| `/api/stats` | GET | données système au format JSON |
| `/api/kill/:pid` | POST | demande de terminaison d’un processus |

Protéger l’accès au serveur et ne pas l’exposer sur Internet sans authentification et contrôle d’accès adaptés.
