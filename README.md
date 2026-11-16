# Servizi Monitor

Controlla ogni 30 minuti siti, biglietterie Webtic, servizi esterni e social e manda una email quando qualcosa va offline (o una biglietteria mostra la pagina bianca). Dashboard protetta da password; nel repo ci sono solo dati cifrati.

- `services.enc.json`: servizi monitorati, cifrati. Per modificarli: `python3 monitor/vault.py open-services`, modifica `services.json` (non va nel repo), poi `python3 monitor/vault.py seal-services`.
- `monitor/check.py`: esegue i controlli. In locale: `python3 monitor/check.py --no-mail` (scrive `docs/data` in chiaro, escluso dal repo).
- `monitor/vault.py`: cifratura AES-256-GCM (chiave PBKDF2 dalla password del sito). Richiede `pip install cryptography`.
- `docs/index.html`: dashboard. In locale: `cd docs && python3 -m http.server 8770`, poi http://localhost:8770 (legge i dati in chiaro).
- `.github/workflows/check.yml`: ogni 30 minuti decifra, controlla, cifra e pubblica il ramo `gh-pages` (una sola commit).

Secrets del repo: `SITE_PASSWORD` (password del sito, stessa usata per `seal-services`), `SMTP_USER`, `SMTP_PASSWORD` (password per le app Gmail), `MAIL_TO`.
Non cambiare `monitor/site_salt.txt`: invaliderebbe i dati cifrati e la chiave ricordata dai browser.
