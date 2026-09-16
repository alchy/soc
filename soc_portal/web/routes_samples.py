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
from functools import lru_cache

from flask import (Blueprint, Response, abort, g, render_template, request,
                   send_file)

import soc_mail

from .. import config, vault_reader
from ..logging_setup import event
from .deps import client_ip, login_required

bp = Blueprint("samples", "samples")

# CSP pro iframe s telem e-mailu: nic se nesmi nacist ani spustit. 'unsafe-inline'
# jen pro styly, aby mail nevypadal rozsypane; skripty a externi zdroje zakazany.
_BODY_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
             "base-uri 'none'; form-action 'none'")
_TEXT_PREVIEW_MAX = 200 * 1024  # kolik textu hlavicek nacist do nahledu

# CSS vkladane do tel v iframe: maily mivaji pevne sirky (tabulky width=600),
# ktere v uzsim ramu vynuti horizontalni scroll. Vse srazime na sirku ramu
# a necháme zalamovat - analytik cte, nescrolluje do stran. !important je
# zamer: prebiji i inline styly zpravy.
_WRAP_CSS = """
body { margin: 8px; overflow-wrap: anywhere; }
* { max-width: 100% !important; min-width: 0 !important; box-sizing: border-box; }
table { width: auto !important; }
td, th { word-break: break-word; }
img { height: auto !important; }
pre { white-space: pre-wrap !important; }
"""


@bp.get("/healthz")
def healthz():
    """Provozni sonda, bez prihlaseni. Nezavisla na AM i na obsahu vaultu."""
    return {"status": "ok", "vault_present": config.VAULT.is_dir()}


@lru_cache(maxsize=2048)
def _triage_summary(sha256: str) -> dict:
    """Souhrn pro radek dashboardu: SKUTECNY odesilatel/predmet (z vnorene
    reportovane zpravy, kdyz existuje) + skore hlavicek.

    lru_cache je tu bezpecna: vzorek ve vaultu je nemenny (obsahove
    adresovany sha256), takze vysledek parsovani se nikdy nemeni. Bez cache
    by kazde nacteni dashboardu parsovalo N x .msg.
    """
    sender = subject = ""
    analysis = None
    nested = vault_reader.list_nested_messages(sha256)
    if nested:
        try:
            parsed = soc_mail.parse_msg(
                vault_reader.extracted_path(sha256, nested[0]))
            sender, subject = parsed.sender, parsed.subject
            analysis = soc_mail.analyze(parsed.headers_text)
        except (soc_mail.MailParseError, vault_reader.VaultError,
                FileNotFoundError):
            pass
    if analysis is None:
        try:
            text = vault_reader.extracted_path(sha256, "headers.txt").read_text(
                encoding="utf-8-sig", errors="replace")
            analysis = soc_mail.analyze(text)
        except (vault_reader.VaultError, FileNotFoundError, OSError):
            pass
    score = soc_mail.score_headers(analysis) if analysis else None
    return {"sender": sender, "subject": subject, "is_report": bool(nested),
            "points": score.points if score else None,
            "band": score.band if score else None}


@bp.get("/")
@login_required
def dashboard():
    try:
        limit = int(request.args.get("limit", config.DEFAULT_LIMIT))
    except ValueError:
        limit = config.DEFAULT_LIMIT
    limit = max(1, min(limit, config.MAX_LIMIT))

    rows = []
    for m in vault_reader.iter_samples()[:limit]:
        row = vault_reader.summarize(m)
        triage = _triage_summary(row["sha256"])
        # radek ukazuje to podstatne: reportovanou zpravu; obal jen jako zaloha
        row["real_sender"] = triage["sender"] or row["sender"]
        row["real_subject"] = triage["subject"] or row["subject"]
        row.update(is_report=triage["is_report"], points=triage["points"],
                   band=triage["band"])
        rows.append(row)
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
    nested = _parse_nested(sha256)

    # Analyza hlavicek OBALU ma smysl, jen kdyz vzorek neni report s vnorenou
    # zpravou - u reportu je obal interni posta a analyza by matla.
    wrapper_analysis = (soc_mail.analyze(headers_text)
                        if headers_text and not nested else None)
    wrapper_score = (soc_mail.score_headers(wrapper_analysis)
                     if wrapper_analysis else None)

    return render_template(
        "sample_detail.html",
        sha256=sha256, manifest=manifest, metadata=metadata or {},
        files=files, events=events, has_body=has_body, headers_text=headers_text,
        nested=nested, wrapper_analysis=wrapper_analysis,
        wrapper_score=wrapper_score, summary=vault_reader.summarize(manifest),
    )


@bp.get("/sample/<sha256>/body")
@login_required
def sample_body(sha256: str):
    """HTML telo e-mailu - defangovane a jen do sandboxovaneho iframe s CSP."""
    try:
        path = vault_reader.extracted_path(_valid_sha(sha256), "body.html")
    except (vault_reader.VaultError, FileNotFoundError):
        abort(404)
    return _hostile_html_response(
        soc_mail.defang_html(path.read_bytes(), inject_css=_WRAP_CSS))


@bp.get("/sample/<sha256>/nested/<int:idx>/body")
@login_required
def nested_body(sha256: str, idx: int):
    """HTML telo VNORENE zpravy (reportovany spam) - defangovane, do sandboxu.

    `idx` je poradi v vault_reader.list_nested_messages(); parsuje se pri
    kazdem pozadavku (stateless, .msg ma radove stovky kB - zadna cache).
    """
    rels = vault_reader.list_nested_messages(_valid_sha(sha256))
    if not 0 <= idx < len(rels):
        abort(404)
    try:
        parsed = soc_mail.parse_msg(vault_reader.extracted_path(sha256, rels[idx]))
    except (soc_mail.MailParseError, vault_reader.VaultError, FileNotFoundError):
        abort(404)
    if not parsed.body_html:
        abort(404)
    return _hostile_html_response(
        soc_mail.defang_html(parsed.body_html, inject_css=_WRAP_CSS))


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
def _hostile_html_response(html: str) -> Response:
    """Odpoved pro nepratelske HTML: prisne CSP, zadny sniffing, zadna cache."""
    return Response(html, mimetype="text/html; charset=utf-8", headers={
        "Content-Security-Policy": _BODY_CSP,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    })


def _parse_nested(sha256: str) -> list[dict]:
    """Rozparsuje vnorene .msg prilohy pro detail. Chybu parsovani NEshazuje -
    analytik musi videt aspon to, ze priloha existuje a ze je necitelna."""
    out = []
    for idx, rel in enumerate(vault_reader.list_nested_messages(sha256)):
        item = {"idx": idx, "path": rel, "msg": None, "body_text": "",
                "analysis": None, "score": None}
        try:
            parsed = soc_mail.parse_msg(vault_reader.extracted_path(sha256, rel))
            item["msg"] = parsed
            item["body_text"] = soc_mail.defang_text(parsed.body_text)
            item["analysis"] = soc_mail.analyze(parsed.headers_text)
            item["score"] = soc_mail.score_headers(item["analysis"])
        except (soc_mail.MailParseError, vault_reader.VaultError,
                FileNotFoundError) as e:
            event(bp_logger(), logging.WARNING, "nested_msg_parse_failed",
                  subject_id=g.identity.subject_id, sha256=sha256,
                  path=rel, detail=str(e))
        out.append(item)
    return out


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
