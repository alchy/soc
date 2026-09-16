"""Routy nad vzorky: dashboard, detail, bezpecne servirovani obsahu.

Cely obsah `extracted/` pochazi z NEPRATELSKEHO vzorku (je to phishing). Proto:
  - HTML telo se servíruje jen do sandboxovaneho iframe s prisnym CSP
    (zadny skript, zadne nacitani obrazku/pixelu, zadny odchozi request),
  - vsechny ostatni soubory jen jako priloha ke stazeni (nikdy inline render),
  - X-Content-Type-Options: nosniff, at prohlizec nedomysli nebezpecny typ.
Analytik se nesmi nechat "popnout" vzorkem, ktery zkouma.
"""
from __future__ import annotations

import logging

from flask import (Blueprint, Response, abort, g, render_template, request,
                   send_file)

from .. import config, vault_reader
from ..logging_setup import event
from .deps import client_ip, login_required

bp = Blueprint("samples", "samples")

# CSP pro iframe s telem e-mailu: nic se nesmi nacist ani spustit. 'unsafe-inline'
# jen pro styly, aby mail nevypadal rozsypane; skripty a externi zdroje zakazany.
_BODY_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
             "base-uri 'none'; form-action 'none'")
_TEXT_PREVIEW_MAX = 200 * 1024  # kolik textu hlavicek nacist do nahledu


@bp.get("/healthz")
def healthz():
    """Provozni sonda, bez prihlaseni. Nezavisla na AM i na obsahu vaultu."""
    return {"status": "ok", "vault_present": config.VAULT.is_dir()}


@bp.get("/")
@login_required
def dashboard():
    try:
        limit = int(request.args.get("limit", config.DEFAULT_LIMIT))
    except ValueError:
        limit = config.DEFAULT_LIMIT
    limit = max(1, min(limit, config.MAX_LIMIT))

    rows = [vault_reader.summarize(m) for m in vault_reader.iter_samples()[:limit]]
    event(bp_logger(), logging.INFO, "dashboard_view",
          subject_id=g.identity.subject_id, remote_ip=client_ip(), shown=len(rows))
    return render_template("dashboard.html", rows=rows, limit=limit)


@bp.get("/sample/<sha256>")
@login_required
def sample_detail(sha256: str):
    manifest = vault_reader.read_manifest(_valid_sha(sha256))
    if manifest is None:
        abort(404)
    metadata = vault_reader.read_metadata(sha256)
    files = vault_reader.list_files(sha256)
    events = vault_reader.read_events(sha256)
    has_body = any(f["path"] == "body.html" for f in files)
    headers_text = _read_text_preview(sha256, "headers.txt")

    return render_template(
        "sample_detail.html",
        sha256=sha256, manifest=manifest, metadata=metadata or {},
        files=files, events=events, has_body=has_body, headers_text=headers_text,
        summary=vault_reader.summarize(manifest),
    )


@bp.get("/sample/<sha256>/body")
@login_required
def sample_body(sha256: str):
    """HTML telo e-mailu - jen do sandboxovaneho iframe, s prisnym CSP."""
    try:
        path = vault_reader.extracted_path(_valid_sha(sha256), "body.html")
    except (vault_reader.VaultError, FileNotFoundError):
        abort(404)
    data = path.read_bytes()
    return Response(data, mimetype="text/html; charset=utf-8", headers={
        "Content-Security-Policy": _BODY_CSP,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    })


@bp.get("/sample/<sha256>/file/<path:relpath>")
@login_required
def sample_file(sha256: str, relpath: str):
    """Stazeni rozbaleneho souboru VZDY jako priloha - nikdy se nerenderuje."""
    try:
        path = vault_reader.extracted_path(_valid_sha(sha256), relpath)
    except vault_reader.VaultError:
        abort(400)
    except FileNotFoundError:
        abort(404)
    event(bp_logger(), logging.INFO, "file_download",
          subject_id=g.identity.subject_id, remote_ip=client_ip(),
          sha256=sha256, path=relpath)
    resp = send_file(path, as_attachment=True, download_name=path.name,
                     mimetype="application/octet-stream")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


# ── pomocne ──────────────────────────────────────────────────────────────────
def _valid_sha(sha256: str) -> str:
    if not vault_reader.SHA256_RE.match(sha256 or ""):
        abort(404)
    return sha256


def _read_text_preview(sha256: str, name: str) -> str | None:
    try:
        path = vault_reader.extracted_path(sha256, name)
    except (vault_reader.VaultError, FileNotFoundError):
        return None
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")[:_TEXT_PREVIEW_MAX]
    except OSError:
        return None


def bp_logger():
    from flask import current_app
    return current_app.logger_soc
