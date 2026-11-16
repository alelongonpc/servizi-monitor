"""Controlla tutti i servizi di services.json e aggiorna docs/data.

Stati: ok, warn (lento / in scadenza / discontinuo / social non raggiungibile), down (offline o pagina vuota).
Logica di allarme (parametri in services.json -> "alert"):
- un servizio che fallisce viene ricontrollato `retries` volte ogni `retry_minutes` minuti;
- se falliscono tutti i tentativi e' OFFLINE: email con l'ora del primo errore, poi promemoria ogni
  `remind_hours` e email quando torna online. Un servizio gia' offline non rifa' i tentativi;
- se fallisce solo in parte: almeno `flaky_min_fails` errori nella finestra, oppure errori in almeno
  `flaky_episodes_24h` controlli nelle ultime 24 ore = DISCONTINUO (avviso + email, ripetuta ogni `remind_hours`).
Variabili email: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, MAIL_TO (senza, l'email viene solo stampata).
RETRY_SECONDS (solo per i test) sostituisce `retry_minutes`.

Uso: python monitor/check.py [--no-mail]
"""
import csv
import json
import os
import smtplib
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
CFG = json.loads((ROOT / "services.json").read_text(encoding="utf-8"))
DATA = ROOT / "docs" / "data"
STATUS = DATA / "status.json"
HISTORY = DATA / "history.csv"
STATE = DATA / "alert_state.json"
HIST_FIELDS = ["ts", "id", "state", "ms", "detail"]
HIST_DAYS = 60
UA = "Mozilla/5.0 ServiziMonitor/1"  # il firewall del sito chiude la connessione agli UA con "compatible;"
WEBTIC_API = "https://secure.webtic.it/api/wtjsonservices.ashx"
TZ = ZoneInfo("Europe/Rome")
AL = CFG.get("alert", {})
RETRIES = AL.get("retries", 10)
RETRY_S = int(os.environ.get("RETRY_SECONDS") or AL.get("retry_minutes", 3) * 60)
FLAKY_FAILS = AL.get("flaky_min_fails", 3)
FLAKY_EPISODES = AL.get("flaky_episodes_24h", 3)
REMIND = timedelta(hours=CFG.get("remind_hours", 6))
QUIET = bool(os.environ.get("GITHUB_ACTIONS"))  # i log di un repo pubblico sono pubblici: niente nomi ne' URL


def log(msg):
    if not QUIET:
        print(msg, flush=True)


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language": "it"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(3_000_000).decode("utf-8", errors="replace")
            code = r.status
    except urllib.error.HTTPError as e:
        body, code = "", e.code
    return code, body, int((time.monotonic() - t0) * 1000)


RANK = {"ok": 0, "warn": 1, "down": 2}


def check_http(s):
    code, body, ms = fetch(s["url"])
    if s.get("soft") and code in (403, 429, 999):  # il social blocca i controlli automatici: non e' un guasto
        return "ok", f"HTTP {code}: limita i controlli automatici", ms
    if code >= 400:
        state, detail = "down", f"HTTP {code}"
    elif s.get("contains") and s["contains"] not in body:
        state, detail = "down", f"HTTP {code} ma contenuto atteso assente"
    elif ms > s.get("slow_ms", 8000):
        state, detail = "warn", f"lento ({ms / 1000:.1f}s)"
    else:
        state, detail = "ok", f"HTTP {code}"
    if s.get("ssl"):  # certificato del sito nella stessa riga, solo come testo: cambia lo stato solo se non e' valido o e' scaduto
        try:
            sst, sdet, _ = check_ssl({"host": s.get("ssl_host") or urllib.parse.urlsplit(s["url"]).hostname})
        except Exception as e:
            sst, sdet = "warn", f"non verificabile ({str(getattr(e, 'reason', None) or e)[:80]})"
        if sst == "down":
            state = "down"
        detail += f" · SSL {sdet}"
    return state, detail, ms


def check_json_list(s):
    code, body, ms = fetch(s["url"])
    if code >= 400:
        return "down", f"HTTP {code}", ms
    try:
        n = len(json.loads(body))
    except (ValueError, TypeError):
        return "down", "risposta non valida", ms
    return ("ok", "catalogo attivo", ms) if n else ("down", "catalogo vuoto", ms)


def check_webtic(s):
    """Pagina bianca = getFullScheduling in errore o senza eventi (i nuovi tentativi li fa main)."""
    url = f"{WEBTIC_API}?localid={s['local_id']}&trackid=33&wtid=getFullScheduling"
    code, body, ms = fetch(url, timeout=60)
    try:
        data = json.loads(body)
    except ValueError:
        return "down", f"HTTP {code}, risposta non valida", ms
    ud = data.get("userdata", {})
    if ud.get("StatusOk") is not True:
        return "down", f"pagina bianca: errore Webtic \"{(ud.get('Message') or '')[:120]}\"", ms
    events = ((data.get("DS") or {}).get("Scheduling") or {}).get("Events") or []
    if not events:
        return "down", "pagina bianca: nessuno spettacolo", ms
    return "ok", f"{len(events)} spettacoli in programma", ms


def check_ssl(s):
    t0 = time.monotonic()
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((s["host"], 443), timeout=20) as sock:
            with ctx.wrap_socket(sock, server_hostname=s["host"]) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return "down", f"certificato non valido: {e.verify_message}", int((time.monotonic() - t0) * 1000)
    ms = int((time.monotonic() - t0) * 1000)
    exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days = (exp - datetime.now(timezone.utc)).days
    if days < 0:
        return "down", "certificato scaduto", ms
    if days < 21:
        return "warn", f"scade tra {days} giorni", ms
    return "ok", f"valido, scade tra {days} giorni", ms


DOMAINS = DATA / "domains.json"  # scadenza dei domini: cache, si aggiorna una volta al giorno
EXPIRY_KEYS = ("expire date", "expiry date", "registry expiry date", "paid-till", "expiration date")


def whois_query(server, query):
    with socket.create_connection((server, 43), timeout=15) as s:
        s.sendall((query + "\r\n").encode())
        buf = b""
        while chunk := s.recv(4096):
            buf += chunk
    return buf.decode(errors="replace")


def whois_expiry(domain):
    """Data di scadenza del dominio (YYYY-MM-DD) dal whois, o None."""
    tld = domain.rsplit(".", 1)[-1]
    server = "whois.nic.it" if tld == "it" else None
    if not server:  # chiede a IANA qual e' il server whois del TLD
        ref = whois_query("whois.iana.org", tld)
        server = next((l.split(":", 1)[1].strip() for l in ref.splitlines() if l.lower().startswith("whois:")), None)
    if not server:
        return None
    for line in whois_query(server, domain).splitlines():
        k, _, v = line.partition(":")
        if k.strip().lower() in EXPIRY_KEYS and v.strip():
            return v.strip()[:10]
    return None


def domain_of(s):
    if s.get("domain"):
        return s["domain"]
    host = urllib.parse.urlsplit(s["url"]).hostname or ""
    return ".".join(host.split(".")[-2:])


def update_domains(services, now):
    cache = load_json(DOMAINS, {})
    for d in sorted({domain_of(s) for s in services if s.get("ssl")}):
        c = cache.get(d, {})
        fresh = c.get("checked") and now - datetime.fromisoformat(c["checked"]) < timedelta(hours=24)
        if fresh and c.get("expires"):
            continue
        try:
            exp = whois_expiry(d)
        except Exception:
            exp = None  # whois irraggiungibile: si tiene il vecchio valore e si riprova al prossimo controllo
        if exp:
            cache[d] = {"expires": exp, "checked": now.isoformat()}
        elif d not in cache:
            cache[d] = {"expires": None, "checked": None}
    DOMAINS.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    return cache


CHECKS = {"http": check_http, "json_list": check_json_list, "webtic": check_webtic, "ssl": check_ssl}


def run_one(s):
    try:
        state, detail, ms = CHECKS[s["type"]](s)
    except Exception as e:  # timeout, DNS, connessione rifiutata...
        reason = getattr(e, "reason", None) or e
        state, detail, ms = "down", f"non raggiungibile ({str(reason)[:120]})", None
        if "CERTIFICATE_VERIFY_FAILED" in str(reason):
            why = "SSL SCADUTO" if "expired" in str(reason) else "SSL NON VALIDO"
            state, detail = "down", f"{why}: il browser mostra \"sito non sicuro\""
    if s.get("soft") and state == "down":
        state = "warn"  # i social bloccano spesso i bot: avviso, non allarme
    return {"id": s["id"], "group": s["group"], "name": s["name"], "type": s["type"], "ssl": bool(s.get("ssl")),
            "url": s.get("url", ""),
            "state": state, "detail": detail, "ms": ms}


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_history(ts, results, now):
    rows = []
    if HISTORY.exists():
        cutoff = (now - timedelta(days=HIST_DAYS)).strftime("%Y-%m-%dT%H:%MZ")
        with HISTORY.open(encoding="utf-8", newline="") as f:
            rows = [r for r in csv.DictReader(f) if r["ts"] >= cutoff]
    rows += [{"ts": ts, "id": r["id"], "state": r["state"], "ms": r["ms"] if r["ms"] is not None else "",
              "detail": r["detail"]} for r in results]
    with HISTORY.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, HIST_FIELDS)
        w.writeheader()
        w.writerows(rows)


def send_mail(subject, body):
    user, pwd, to = (os.environ.get(k, "") for k in ("SMTP_USER", "SMTP_PASSWORD", "MAIL_TO"))
    if not (user and pwd and to):
        log(f"[email non configurata] {subject}\n{body}")
        return False
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, user, to
    msg.set_content(body)
    host, port = os.environ.get("SMTP_HOST", "smtp.gmail.com"), int(os.environ.get("SMTP_PORT", "465"))
    with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=60) as smtp:
        smtp.login(user, pwd)
        smtp.send_message(msg)
    return True


def local(dt):
    return dt.astimezone(TZ).strftime("%d/%m %H:%M")


def dur(td):
    m = int(td.total_seconds() // 60)
    if m < 60:
        return f"{m} min"
    h, m = divmod(m, 60)
    if h < 48:
        return f"{h} h {m:02d} min"
    return f"{h // 24} giorni {h % 24} h"


def run_all(services):
    with ThreadPoolExecutor(max_workers=8) as ex:
        return list(ex.map(run_one, services))


def confirm(cands, by_cfg):
    """Ricontrolla i servizi falliti RETRIES volte ogni RETRY_S secondi. Ritorna errori e ultimo esito buono."""
    fails = {i: 1 for i in cands}
    last_ok, last_bad = {}, {}
    nxt = time.monotonic()
    for n in range(RETRIES):
        nxt += RETRY_S
        time.sleep(max(0, nxt - time.monotonic()))
        for r in run_all([by_cfg[i] for i in cands]):
            if r["state"] == "down":
                fails[r["id"]] += 1
                last_bad[r["id"]] = r
            else:
                last_ok[r["id"]] = r
        log(f"tentativo {n + 1}/{RETRIES}: " + ", ".join(f"{i} {fails[i]} errori" for i in cands))
    return fails, last_ok, last_bad


def evaluate(results, svc, now, ts):
    """Applica la logica di conferma e ritorna gli eventi da segnalare."""
    by_cfg = {s["id"]: s for s in CFG["services"]}
    res = {r["id"]: r for r in results}
    cands = [i for i, r in res.items() if r["state"] == "down" and svc.get(i, {}).get("status") != "down"]
    fails, last_ok, last_bad = ({}, {}, {})
    if cands:
        print(f"Da confermare: {len(cands)} servizi ({RETRIES} tentativi ogni {RETRY_S}s)", flush=True)
        log(", ".join(cands))
        fails, last_ok, last_bad = confirm(cands, by_cfg)
    total = RETRIES + 1
    day_ago = (now - timedelta(hours=24)).isoformat()
    ev = {"down": [], "up": [], "flaky": [], "remind": []}
    for i, r in res.items():
        s = svc.setdefault(i, {})
        s["episodes"] = [e for e in s.get("episodes", []) if e >= day_ago]
        if i in cands:
            if fails[i] == total:  # tutti i tentativi falliti: offline confermato
                r.update({k: last_bad.get(i, r)[k] for k in ("detail", "ms")})
                s.update(status="down", first_fail=now.isoformat(), last_mail=None)
                r["since"] = ts
                ev["down"].append(i)
                continue
            r.update({k: last_ok[i][k] for k in ("state", "detail", "ms")})
            s["episodes"].append(now.isoformat())
            if fails[i] >= FLAKY_FAILS or len(s["episodes"]) >= FLAKY_EPISODES:
                why = (f"{fails[i]} tentativi falliti su {total} in {RETRIES * RETRY_S // 60} min"
                       if fails[i] >= FLAKY_FAILS else f"errori in {len(s['episodes'])} controlli nelle ultime 24 ore")
                s["flaky_why"] = why
                if s.get("status") != "flaky":
                    s.update(status="flaky", flaky_since=now.isoformat(), last_mail=None)
        if s.get("status") == "down":
            if r["state"] == "down":
                r["since"] = datetime.fromisoformat(s["first_fail"]).strftime("%Y-%m-%dT%H:%MZ")
                if not s.get("last_mail") or now - datetime.fromisoformat(s["last_mail"]) >= REMIND:
                    ev["remind"].append(i)
                continue
            s["recovered_after"] = dur(now - datetime.fromisoformat(s["first_fail"]))
            ev["up"].append(i)
            s.update(status=None, last_mail=None)
        if s.get("status") == "flaky":
            last_ep = s["episodes"][-1] if s["episodes"] else None
            if not last_ep or now - datetime.fromisoformat(last_ep) >= REMIND:
                s.update(status=None, last_mail=None)  # nessun errore da remind_hours: torna normale
            else:
                if r["state"] == "ok":
                    r["state"] = "warn"
                r["detail"] = f"discontinuo: {s['flaky_why']} (ultimo errore {local(datetime.fromisoformat(last_ep))})"
                if not s.get("last_mail") or now - datetime.fromisoformat(s["last_mail"]) >= REMIND:
                    ev["flaky"].append(i)
    return ev


def alert(ev, results, svc, now, mail_enabled):
    if not any(ev.values()):
        return
    by_id = {r["id"]: r for r in results}
    name = lambda i: by_id[i]["name"]
    since = lambda i: datetime.fromisoformat(svc[i]["first_fail"])
    lines = []
    if ev["down"]:
        lines.append(f"OFFLINE (confermato: {RETRIES + 1} controlli falliti in {RETRIES * RETRY_S // 60} minuti):")
        lines += [f"- {name(i)}: offline dal {local(since(i))} (da {dur(now - since(i))})\n"
                  f"  {by_id[i]['detail']}\n  {by_id[i]['url']}" for i in ev["down"]]
    if ev["remind"]:
        lines.append("\nANCORA OFFLINE:")
        lines += [f"- {name(i)}: offline dal {local(since(i))} (da {dur(now - since(i))})\n"
                  f"  {by_id[i]['detail']}\n  {by_id[i]['url']}" for i in ev["remind"]]
    if ev["flaky"]:
        lines.append("\nFUNZIONAMENTO DISCONTINUO (va e viene):")
        lines += [f"- {name(i)}: {svc[i]['flaky_why']}, segnalato dal "
                  f"{local(datetime.fromisoformat(svc[i]['flaky_since']))}\n  {by_id[i]['url']}" for i in ev["flaky"]]
    if ev["up"]:
        lines.append("\nTORNATI ONLINE:")
        lines += [f"- {name(i)}: era offline da {svc[i].pop('recovered_after', '?')}" for i in ev["up"]]
    lines.append(f"\nControllo delle {local(now)} (ora italiana)")
    if ev["down"]:
        subject = f"OFFLINE: {', '.join(name(i) for i in ev['down'])}"
    elif ev["flaky"]:
        subject = f"Discontinuo: {', '.join(name(i) for i in ev['flaky'])}"
    elif ev["up"]:
        subject = f"Di nuovo online: {', '.join(name(i) for i in ev['up'])}"
    else:
        subject = f"Ancora offline: {', '.join(name(i) for i in ev['remind'])}"
    sent = False
    if mail_enabled:
        try:
            sent = send_mail(f"[Servizi Monitor] {subject}", "\n".join(lines))
        except Exception as e:
            print(f"ERRORE invio email: {type(e).__name__}")
            log(str(e))
    else:
        log(f"[email disattivata] {subject}\n" + "\n".join(lines))
    if sent:
        for i in ev["down"] + ev["remind"] + ev["flaky"]:
            svc[i]["last_mail"] = now.isoformat()


def main():
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%MZ")
    DATA.mkdir(parents=True, exist_ok=True)
    prev = {c["id"]: c for c in load_json(STATUS, {}).get("checks", [])}
    svc = load_json(STATE, {}).get("services", {})
    results = run_all(CFG["services"])
    doms = update_domains(CFG["services"], now)
    for r, s in zip(results, CFG["services"]):  # dominio e scadenza (solo testo) per i siti
        if s.get("ssl"):
            d = domain_of(s)
            r["domain"], r["domain_expires"] = d, doms.get(d, {}).get("expires")
            r["host"] = urllib.parse.urlsplit(s["url"]).hostname
    for r in results:  # "da quando" e' in questo stato
        p = prev.get(r["id"])
        r["since"] = p["since"] if p and p["state"] == r["state"] and p.get("since") else ts
    ev = evaluate(results, svc, now, ts)
    for r in results:  # lo stato puo' essere cambiato dopo i tentativi
        p = prev.get(r["id"])
        if svc.get(r["id"], {}).get("status") != "down":
            r["since"] = p["since"] if p and p["state"] == r["state"] and p.get("since") else ts
    STATUS.write_text(json.dumps({"ts": ts, "groups": CFG["groups"], "checks": results},
                                 ensure_ascii=False, indent=1), encoding="utf-8")
    save_history(ts, results, now)
    alert(ev, results, svc, now, "--no-mail" not in sys.argv)
    ids = {s["id"] for s in CFG["services"]}  # dimentica i servizi tolti da services.json
    svc = {i: s for i, s in svc.items() if i in ids and (s.get("status") or s.get("episodes"))}
    STATE.write_text(json.dumps({"services": svc}, indent=1), encoding="utf-8")
    for r in results:
        log(f"{r['state']:>4}  {r['name']}: {r['detail']}")
    count = {s: sum(r["state"] == s for r in results) for s in ("ok", "warn", "down")}
    print(f"{len(results)} servizi: {count['ok']} ok, {count['warn']} avvisi, {count['down']} offline; "
          f"email: {', '.join(k for k, v in ev.items() if v) or 'nessuna'}")


if __name__ == "__main__":
    main()
