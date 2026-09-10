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

import shutil
from pathlib import Path

from flask import Flask, jsonify, request

from . import auth, config, extract, storage

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES + 1024 * 1024


# ── pomocne ──────────────────────────────────────────────────────────────────

def client_ip() -> str:
    """Skutecna adresa klienta.

    Hlavickam se veri jen tehdy, kdyz spojeni prislo od nasi vlastni proxy;
    jinak by si kdokoli mohl origin ACL prepsat sam.
    """
    peer = request.remote_addr or ""
    if peer in config.TRUSTED_PROXIES:
        fwd = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return peer


def bearer() -> str | None:
    h = request.headers.get("Authorization", "")
    return h[7:].strip() if h.lower().startswith("bearer ") else None


def caller() -> dict:
    """Overi volajiciho, nebo vyhodi AuthError (viz handler nize)."""
    return auth.authenticate(bearer(), client_ip())


@app.errorhandler(auth.AuthError)
def _auth_error(e: auth.AuthError):
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

@app.get("/api/v1/healthz")
def healthz():
    ok = config.VAULT.is_dir()
    return jsonify({"status": "ok" if ok else "degraded",
                    "vault": str(config.VAULT),
                    "vault_writable": ok}), (200 if ok else 503)
