"""Prezentacni kontrakt - analyza jako sekvence TYPOVANYCH BLOKU.

Toto je hranice mezi analyzou a zobrazenim. Orchestrator sem prelozi vysledky
soc_mail na report, ktery ctou DVE prezentacni komponenty (soc_api jako JSON,
soc_portal jako HTML). Kazdy blok ma `type` a pole daneho typu; prezentacni
vrstva iteruje `blocks` a rendruje podle `type` - nezna semantiku analyzy,
zna jen slovnik bloku. Novy signal = orchestrator vyda dalsi blok znameho
typu; portal se menit nemusi. Neznamy typ prezentacni vrstva preskoci
(dopredna kompatibilita).

Slovnik bloku (v1):
  score          {points, band}                          - stitek skore (semafor)
  alert          {severity, what, comment, points}       - barevny box signalu
  auth           {verifiers:[{server,spf,dkim,dmarc,authoritative,original}]}
  facts          {title, rows:[{label,value}]}            - kv tabulka
  delivery_path  {hops:[{from,info,by,when,count}]}
  message        {sender,subject,date,attachments:[{name,size}]}
  diagnostic     {component,error}                        - selhana komponenta
  body*          {kind:html|text, ref}                    - REZERVOVANO (render faze 2)
  preview*       {ref, caption}                           - REZERVOVANO (PDF nahled)

Report navic nese `verdict` a `summary` na vrchu - to je zkratka pro dashboard,
aby nemusel prochazet bloky.
"""
from __future__ import annotations

from dataclasses import asdict

REPORT_SCHEMA = 1

_SEVERITY = ("info", "low", "medium", "high", "critical")


def _facts_rows(header) -> list[dict]:
    pairs = [
        ("From", f"{header.from_display} <{header.from_addr}>".strip(" <>")),
        ("Sender", header.sender),
        ("To", header.to),
        ("Reply-To", header.reply_to),
        ("Return-Path", header.return_path),
        ("Message-ID", header.message_id),
        ("X-Mailer", header.mailer),
    ]
    return [{"label": k, "value": v} for k, v in pairs if v]


def build_report(sha256, header, score, *, reported=None, received_at="",
                 failures=()) -> dict:
    """Slozi report z vysledku soc_mail. `header` je HeaderAnalysis, `score`
    je Score, `reported` volitelny dict o vnorene zprave."""
    blocks: list[dict] = [{"type": "score", "points": score.points,
                           "band": score.band}]

    if reported:
        blocks.append({"type": "message", **reported})

    for c in score.contributions:
        blocks.append({"type": "alert", "severity": c.level, "what": c.title,
                       "comment": c.text, "points": c.points})

    if header.auth:
        blocks.append({"type": "auth", "verifiers": [
            {"server": r.server, "spf": r.spf, "dkim": r.dkim, "dmarc": r.dmarc,
             "authoritative": r.authoritative, "original": r.original}
            for r in header.auth]})

    rows = _facts_rows(header)
    if rows:
        blocks.append({"type": "facts", "title": "Headers", "rows": rows})

    if header.hops:
        blocks.append({"type": "delivery_path", "hops": [
            {"from": h.from_host, "info": h.from_info, "by": h.by_host,
             "when": h.when, "count": h.count} for h in header.hops]})

    for f in failures:
        blocks.append({"type": "diagnostic", "component": f.component,
                       "error": f.error})

    summary = {
        "sender": (reported or {}).get("sender") or header.from_addr,
        "subject": (reported or {}).get("subject", ""),
        "received_at": received_at,
        "is_report": bool(reported),
    }
    return {
        "schema": REPORT_SCHEMA,
        "sample": sha256,
        "verdict": {"points": score.points, "band": score.band},
        "summary": summary,
        "blocks": blocks,
    }
