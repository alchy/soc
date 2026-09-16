"""Skorovani signalu z hlavicek - priprava na plnohodnotny scoring vzorku.

Zamerne PRUHLEDNE: skore je proste soucet bodu za jednotlive signaly
(sila signalu -> body, viz _LEVEL_POINTS) a vraci se i rozpad na prispevky,
aby analytik videl PROC. Zadna cerna skrinka, zadne ML - vazeni se ladi
zmenou tabulek tady, na jednom miste.

Slaby signal je porad signal: i "info" nese bod. Az pribudou dalsi zdroje
(telo, prilohy, online obohaceni - faze B), pridaji se sem dalsi score_*
funkce a celkove skore bude jejich souctem; kontrakt Score se nemeni.
"""
from __future__ import annotations

from dataclasses import dataclass

from .headers import HeaderAnalysis

# sila signalu (petistupnova skala) -> body; critical vycniva zamerne
_LEVEL_POINTS = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 6}

# vysledek SPF/DKIM/DMARC -> sila signalu (pass a neznamo nebodujeme)
_AUTH_LEVEL = {
    "fail": "high", "permerror": "high",
    "softfail": "medium",
    "none": "low", "temperror": "low",
    "neutral": "info", "policy": "info",
}

# prahy pro semafor: od kolika bodu je pasmo zlute/cervene
_BAND_WARN = 3
_BAND_HIGH = 6


@dataclass(frozen=True)
class Contribution:
    """Jeden prispevek do skore - co (kategorie), jak silne a za kolik bodu."""
    code: str
    title: str                      # kategorie pro UI (SPF, DKIM, PHP skript...)
    text: str
    level: str                      # info|low|medium|high|critical
    points: int


@dataclass(frozen=True)
class Score:
    points: int
    band: str                       # 'ok' | 'info' | 'warn' | 'high' (semafor)
    contributions: tuple[Contribution, ...]


def _band(points: int) -> str:
    if points >= _BAND_HIGH:
        return "high"
    if points >= _BAND_WARN:
        return "warn"
    return "info" if points else "ok"


def score_headers(a: HeaderAnalysis) -> Score:
    """Sesbira bodovane signaly z analyzy hlavicek do jednoho skore."""
    contribs: list[Contribution] = []

    # Autentizace: za kazdy mechanismus NEJHORSI vysledek napric overovateli
    # (kazda brana po ceste pridava vlastni Authentication-Results; utocnikovi
    # staci projit jednou, proto pocitame pesimisticky).
    for mech in ("spf", "dkim", "dmarc"):
        vals = [getattr(r, mech) for r in a.auth if getattr(r, mech)]
        if not vals:
            continue
        worst = max(vals, key=lambda v: _LEVEL_POINTS.get(_AUTH_LEVEL.get(v, ""), 0))
        level = _AUTH_LEVEL.get(worst)
        if level:
            contribs.append(Contribution(
                code=f"{mech}_{worst}", title=mech.upper(),
                text=f"vysledek overeni: {worst}",
                level=level, points=_LEVEL_POINTS[level]))

    for f in a.findings:
        contribs.append(Contribution(
            code=f.code, title=f.title, text=f.text, level=f.level,
            points=_LEVEL_POINTS.get(f.level, 1)))

    points = sum(c.points for c in contribs)
    return Score(points=points, band=_band(points), contributions=tuple(contribs))
