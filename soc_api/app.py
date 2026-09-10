"""soc-api - prijem a evidence malware vzorku.

Zdrojem je VZOREK, adresovany svym sha256. Protoze je zdroj obsahove
adresovany, je prijem prirozene idempotentni: tentyz vzorek podruhe neni
chyba ani duplikat v ulozisti, jen dalsi radek v jeho access.log.

    POST /api/v1/samples                 prijem     -> 201, pri duplicite 200
    GET  /api/v1/samples?limit=N         poslednich N
    GET  /api/v1/samples/<sha256>        manifest
    GET  /api/v1/samples/<sha256>/events access.log
    GET  /api/v1/samples/<sha256>/files  rozbalene soubory
    GET  /api/v1/samples/<sha256>/analysis  stav analyzy (zatim pending)
    GET  /api/v1/healthz                 provoz, bez klice
"""
from __future__ import annotations

import json
import logging
import shutil
import sys
import time
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, g, jsonify, request

from . import auth, config, extract, storage

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES + 1024 * 1024


# ── access log ───────────────────────────────────────────────────────────────
# Jeden radek na pozadavek, JSONL - obdoba access logu proxy, ale s tim, co
# proxy vedet nemuze: kterym klicem se kdo prokazal a jakeho vzorku se to
# tykalo. Pise se do souboru v namontovanem adresari, takze zaznamy prezijou
# smazani kontejneru; provozni log (event/auth_denied) zustava na stdout.

_access = logging.getLogger("soc.access")
_access.propagate = False

if config.LOG_DIR:
    _dir = Path(config.LOG_DIR)
    _dir.mkdir(parents=True, exist_ok=True)
    _h = RotatingFileHandler(_dir / "access.log", maxBytes=config.LOG_MAX_BYTES,
                             backupCount=config.LOG_BACKUPS, encoding="utf-8")
    _h.setFormatter(logging.Formatter("%(message)s"))
    _access.addHandler(_h)
    _access.setLevel(logging.INFO)


# ── provozni log ─────────────────────────────────────────────────────────────
# Jeden radek, jeden JSON objekt - stejny tvar jako u access-manageru.
# Bezny provoz na stdout, potize na stderr: odmitnuty pozadavek NENI chyba
# procesu, sluzba se prave zachovala spravne. Trideni podle proudu pak dela
# `grep stderr` uzitecnou triaz.

def log(event: str, *, err: bool = False, **fields) -> None:
    line = json.dumps({"t": datetime.now(UTC).isoformat(timespec="seconds"),
                       "event": event, **fields}, ensure_ascii=False, sort_keys=True)
    print(line, file=sys.stderr if err else sys.stdout, flush=True)


@app.before_request
def _start_timer():
    g.started = time.monotonic()


@app.after_request
def _access_log(response):
    """Zapise radek o pozadavku. Bezi i u chyb - error handlery vraci response."""
    if not _access.handlers:
        return response
    ip, trusted = resolve_client()
    rec = {
        "t": datetime.now(UTC).isoformat(timespec="seconds"),
        "method": request.method,
        "path": request.path,
        "status": response.status_code,
        "client_ip": ip,
        "peer": request.remote_addr,
        "trusted_proxy": trusted,
        "bytes_in": request.content_length or 0,
        "duration_ms": round((time.monotonic() - getattr(g, "started", 0)) * 1000, 1),
    }
    # Doplni se jen kdyz je co doplnit - prazdna pole by predstirala, ze se
    # merila a nic nevysla.
    for pole in ("component", "key_id", "sha256", "outcome"):
        if (v := g.get(pole)) is not None:
            rec[pole] = v
    _access.info(json.dumps(rec, ensure_ascii=False, sort_keys=True))
    return response


# ── pomocne ──────────────────────────────────────────────────────────────────

def resolve_client() -> tuple[str, bool]:
    """Vraci (adresa klienta, veri se hlavicce?).

    Hlavickam se veri jen tehdy, kdyz spojeni prislo od nasi vlastni proxy;
    jinak by si kdokoli mohl origin ACL prepsat sam.

    Pozor pri behu v kontejneru: proxy NENI videt na 127.0.0.1. Pasta preklada
    zdrojovou adresu na adresu hostitele, takze `SOC_TRUSTED_PROXIES` musi
    obsahovat prave ji. Kdyz nesedi, vraci se sem adresa proxy a origin ACL
    v access-manageru prestane rozlisovat klienty - proto to `trusted` nize
    konci v logu u kazdeho odmitnuti.
    """
    peer = request.remote_addr or ""
    trusted = peer in config.TRUSTED_PROXIES
    if trusted:
        fwd = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip(), True
    return peer, trusted


def client_ip() -> str:
    return resolve_client()[0]


def bearer() -> str | None:
    h = request.headers.get("Authorization", "")
    return h[7:].strip() if h.lower().startswith("bearer ") else None


def caller() -> dict:
    """Overi volajiciho, nebo vyhodi AuthError (viz handler nize)."""
    who = auth.authenticate(bearer(), client_ip())
    g.component, g.key_id = who["component"], who["key_id"]
    return who


@app.errorhandler(auth.AuthError)
def _auth_error(e: auth.AuthError):
    # `peer` vs `client_ip` je diagnostika na tu nejzradnejsi chybu nasazeni:
    # kdyz se `trusted` hlasi false a peer je adresa proxy, jde do
    # access-manageru jako origin proxy misto klienta a origin ACL
    # nerozlisuje nic - pritom to zvenku vypada funkcne.
    ip, trusted = resolve_client()
    log("auth_denied", err=True, error=e.error, path=request.path,
        peer=request.remote_addr, client_ip=ip, trusted_proxy=trusted)
    return jsonify({"error": e.error, "detail": e.detail}), e.status


@app.errorhandler(413)
def _too_large(_):
    return jsonify({"error": "too_large",
                    "detail": f"maximum je {config.MAX_UPLOAD_BYTES} B",
                    "max_bytes": config.MAX_UPLOAD_BYTES}), 413


def _summary(m: dict) -> dict:
    """Zaznam do vypisu - bez podrobnosti, ktere patri do detailu."""
    return {k: m[k] for k in ("sha256", "md5", "sha1", "size", "filename",
                              "received_at", "state") if k in m} | {
        "extraction": {"status": m.get("extraction", {}).get("status"),
                       "file_count": m.get("extraction", {}).get("file_count", 0)},
        "event_count": m.get("event_count", 0),
    }


# ── prijem ───────────────────────────────────────────────────────────────────

@app.post("/api/v1/samples")
def upload():
    who = caller()
    ip = client_ip()

    # Prijmeme obe podoby: multipart (formular, nastroje) i syrove telo (curl).
    #
    # Na `request.files` se sahá JEN u skutecneho multipartu. Werkzeug totiz
    # parsuje formular lazy - az pri prvnim pristupu k files/form - a tim
    # vycerpa `request.stream`. U `--data-binary` (curl posila urlencoded)
    # by pak do vaultu doslo prazdne telo.
    ctype = (request.content_type or "").lower()
    if ctype.startswith("multipart/form-data") and "file" in request.files:
        fs = request.files["file"]
        stream, filename = fs.stream, fs.filename
    else:
        stream = request.stream
        filename = request.headers.get("X-Filename") or "sample.bin"

    tmp, digests, over = storage.receive(stream, config.MAX_UPLOAD_BYTES)
    if over:
        tmp.unlink(missing_ok=True)
        return jsonify({"error": "too_large",
                        "detail": f"maximum je {config.MAX_UPLOAD_BYTES} B",
                        "max_bytes": config.MAX_UPLOAD_BYTES}), 413
    if digests["size"] == 0:
        tmp.unlink(missing_ok=True)
        return jsonify({"error": "empty_body", "detail": "prazdne telo pozadavku"}), 400

    sha256 = digests["sha256"]

    # Nepovinna kontrola integrity: klient smi rict, co ceka.
    expected = (request.headers.get("X-Expected-SHA256") or "").strip().lower()
    if expected and expected != sha256:
        tmp.unlink(missing_ok=True)
        g.outcome = "hash_mismatch"
        return jsonify({"error": "hash_mismatch", "detail": "prenos neodpovida ocekavanemu hashi",
                        "expected": expected, "actual": sha256}), 422

    name = storage.safe_filename(filename)
    d = storage.sample_dir(sha256)
    existing = storage.read_manifest(sha256)

    event = {"event": "upload", "remote_ip": ip, "component": who["component"],
             "key_id": who["key_id"], "realm": who["realm"],
             "filename": name, "size": digests["size"], "sha256": sha256,
             "duplicate": existing is not None}

    if existing is not None:
        # Tentyz obsah uz mame. Original se NEPREPISUJE - je to tyz byte za byte.
        # Pokus se ale zapise: "kdo to poslal znovu" je pro SOC informace.
        tmp.unlink(missing_ok=True)
        storage.log_event(sha256, event)
        existing["event_count"] = len(storage.read_events(sha256))
        storage.write_manifest(sha256, existing)
        g.sha256, g.outcome = sha256, "duplicate"
        return jsonify(existing | {"duplicate": True}), 200

    (d / "original").mkdir(parents=True, exist_ok=True)
    original = d / "original" / name
    shutil.move(str(tmp), str(original))
    original.chmod(0o640)

    storage.log_event(sha256, event)

    result = extract.extract(original, d / "extracted")
    storage.log_event(sha256, {"event": "extract", **result.as_dict()})

    manifest = {
        **digests,
        "filename": name,
        "received_at": storage.now(),
        "received_from": ip,
        "received_by": {"component": who["component"], "key_id": who["key_id"],
                        "realm": who["realm"]},
        "state": "extracted" if result.status == "extracted" else "received",
        "extraction": result.as_dict(),
        "analysis": {"state": "pending"},
        "event_count": len(storage.read_events(sha256)),
    }
    storage.write_manifest(sha256, manifest)

    g.sha256, g.outcome = sha256, "stored"
    return jsonify(manifest), 201, {"Location": f"/api/v1/samples/{sha256}"}


# ── vypisy ───────────────────────────────────────────────────────────────────

@app.get("/api/v1/samples")
def list_samples():
    caller()
    try:
        limit = int(request.args.get("limit", config.DEFAULT_LIMIT))
    except ValueError:
        return jsonify({"error": "bad_request", "detail": "limit musi byt cislo"}), 400
    limit = max(1, min(limit, config.MAX_LIMIT))

    # access.log se prikladá jen na vyzadani - jinak by vypis 200 vzorku
    # narostl o vsechny jejich udalosti.
    want_events = "events" in request.args.get("include", "")

    samples = storage.iter_samples()[:limit]
    out = []
    for m in samples:
        rec = _summary(m)
        if want_events:
            rec["events"] = storage.read_events(m["sha256"])
        out.append(rec)

    return jsonify({"count": len(out), "limit": limit, "samples": out})


@app.get("/api/v1/samples/<sha256>")
def get_sample(sha256: str):
    who = caller()
    sha256 = sha256.lower()
    if not storage.SHA256_RE.match(sha256):
        return jsonify({"error": "bad_request", "detail": "sha256 ma 64 hex znaku"}), 400
    m = storage.read_manifest(sha256)
    if m is None:
        return jsonify({"error": "not_found", "sha256": sha256}), 404

    storage.log_event(sha256, {"event": "read", "remote_ip": client_ip(),
                               "component": who["component"], "key_id": who["key_id"]})
    g.sha256 = sha256
    m["events"] = storage.read_events(sha256)
    m["files"] = storage.list_files(sha256)
    return jsonify(m)


@app.get("/api/v1/samples/<sha256>/events")
def get_events(sha256: str):
    caller()
    sha256 = sha256.lower()
    if storage.read_manifest(sha256) is None:
        return jsonify({"error": "not_found", "sha256": sha256}), 404
    events = storage.read_events(sha256)
    return jsonify({"sha256": sha256, "count": len(events), "events": events})


@app.get("/api/v1/samples/<sha256>/files")
def get_files(sha256: str):
    caller()
    sha256 = sha256.lower()
    m = storage.read_manifest(sha256)
    if m is None:
        return jsonify({"error": "not_found", "sha256": sha256}), 404
    files = storage.list_files(sha256)
    return jsonify({"sha256": sha256, "extraction": m.get("extraction", {}),
                    "count": len(files), "files": files})


@app.get("/api/v1/samples/<sha256>/analysis")
def get_analysis(sha256: str):
    caller()
    sha256 = sha256.lower()
    m = storage.read_manifest(sha256)
    if m is None:
        return jsonify({"error": "not_found", "sha256": sha256}), 404
    # Misto pro analyzator. Stav je v manifestu od zacatku, takze az prijde,
    # pribudou jen HODNOTY do existujiciho pole - klienti se nemusi menit.
    return jsonify({"sha256": sha256, **m.get("analysis", {"state": "pending"})})


# ── provoz ───────────────────────────────────────────────────────────────────

log("starting", vault=str(config.VAULT), am_url=config.AM_URL,
    am_realm=config.AM_REALM, trusted_proxies=list(config.TRUSTED_PROXIES),
    max_upload=config.MAX_UPLOAD_BYTES)


@app.get("/api/v1/healthz")
def healthz():
    ok = config.VAULT.is_dir()
    return jsonify({"status": "ok" if ok else "degraded",
                    "vault": str(config.VAULT),
                    "vault_writable": ok}), (200 if ok else 503)
