"""Cifratura per il repo pubblico: nel repo vanno solo file cifrati, mai services.json o docs/data in chiaro.

AES-256-GCM, chiave = PBKDF2-SHA256(password, monitor/site_salt.txt, 600000 iter), dati compressi gzip
(stesso formato di Biglietti Monitor, leggibile da WebCrypto nella dashboard).
Password: variabile SITE_PASSWORD, poi Portachiavi macOS (servizio servizi-monitor), altrimenti viene chiesta. Richiede `pip install cryptography`.

Comandi:
  python monitor/vault.py seal-services     services.json -> services.enc.json (dopo ogni modifica a services.json)
  python monitor/vault.py open-services     services.enc.json -> services.json
  python monitor/vault.py pack CARTELLA     docs/data (stato, storico, allarmi) -> CARTELLA/data.enc.json
  python monitor/vault.py unpack FILE       FILE (data.enc.json) -> docs/data (se FILE manca: primo avvio, nulla)
"""
import base64
import getpass
import subprocess
import gzip
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "data"
ITER = 600_000
SALT = bytes.fromhex((Path(__file__).parent / "site_salt.txt").read_text().strip())
FILES = {"status": "status.json", "history": "history.csv", "state": "alert_state.json", "domains": "domains.json"}



def keychain_pw():
    """Su macOS: password salvata nel Portachiavi (servizio 'servizi-monitor'), se presente."""
    try:
        r = subprocess.run(["security", "find-generic-password", "-s", "servizi-monitor", "-w"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None

def key():
    pw = os.environ.get("SITE_PASSWORD") or keychain_pw() or getpass.getpass("Password del sito: ")
    if len(pw) < 8:
        sys.exit("password mancante o troppo corta (minimo 8 caratteri)")
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), SALT, ITER, 32)


def seal(obj, k):
    raw = gzip.compress(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), mtime=0)
    iv = os.urandom(12)
    return {"v": 1, "alg": "AES-256-GCM", "kdf": "PBKDF2-SHA256", "iter": ITER,
            "salt": base64.b64encode(SALT).decode(), "iv": base64.b64encode(iv).decode(),
            "ct": base64.b64encode(AESGCM(k).encrypt(iv, raw, None)).decode()}


def unseal(enc, k):
    try:
        raw = AESGCM(k).decrypt(base64.b64decode(enc["iv"]), base64.b64decode(enc["ct"]), None)
    except Exception:
        sys.exit("decifratura fallita: password errata o file danneggiato")
    return json.loads(gzip.decompress(raw))


def main():
    cmd, arg = (sys.argv[1:] + ["", ""])[:2]
    if cmd == "seal-services":
        services = json.loads((ROOT / "services.json").read_text(encoding="utf-8"))
        (ROOT / "services.enc.json").write_text(json.dumps(seal(services, key())))
        print("services.enc.json aggiornato")
    elif cmd == "open-services":
        enc = json.loads((ROOT / "services.enc.json").read_text())
        (ROOT / "services.json").write_text(json.dumps(unseal(enc, key()), ensure_ascii=False, indent=2),
                                            encoding="utf-8")
        print("services.json decifrato")
    elif cmd == "pack" and arg:
        payload = {}
        for name, fn in FILES.items():
            p = DATA / fn
            if p.exists():
                text = p.read_text(encoding="utf-8")
                payload[name] = text if fn.endswith(".csv") else json.loads(text)
        out = Path(arg)
        out.mkdir(parents=True, exist_ok=True)
        (out / "data.enc.json").write_text(json.dumps(seal(payload, key())))
        print(f"{out / 'data.enc.json'}: {(out / 'data.enc.json').stat().st_size // 1024} KB cifrati")
    elif cmd == "unpack" and arg:
        p = Path(arg)
        if not p.exists() or not p.stat().st_size:
            print("nessun dato precedente (primo avvio)")
            return
        payload = unseal(json.loads(p.read_text()), key())
        DATA.mkdir(parents=True, exist_ok=True)
        for name, fn in FILES.items():
            if name in payload:
                v = payload[name]
                (DATA / fn).write_text(v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
        print("dati precedenti ripristinati")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
