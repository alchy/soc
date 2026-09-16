"""Skorovani signalu z hlavicek - priprava na plnohodnotny scoring vzorku.

Zamerne PRUHLEDNE: skore je proste soucet bodu za jednotlive signaly
(sila signalu -> body, viz _LEVEL_POINTS) a vraci se i rozpad na prispevky,
aby analytik videl PROC. Zadna cerna skrinka, zadne ML - vazeni se ladi
zmenou tabulek tady, na jednom miste.

!!! VAHY JSOU ZATIM NEKALIBROVANE HEURISTIKY !!!
Body i prahy pasem (_LEVEL_POINTS, _AUTH_LEVEL, _BAND_*) jsou odhad od stolu,
ne cislo overene proti otagovanemu korpusu posty. "Skore 19" NENI merena
pravdepodobnost - je to soucet vah, ktery slouzi k RAZENI a upozorneni, ne
jako verdikt. Az budou k dispozici triazovane vzorky (rozhodnuti analytiku),
tyhle tabulky se maji podle nich doladit. Skore je pomucka, ne rozsudek.

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

    # Autentizace: boduje se verdikt AUTORITATIVNIHO overovatele (vstupni
    # brana - jedina, ktera videla skutecnou IP; viz AuthResult). SPF od
    # pozdejsich overovatelu je artefakt hybridu a NIKDY se neboduje - jinak
    # bychom trestali i legitimni postu. DKIM (kryptograficky) a DMARC
    # (DNS politika) maji smysl i pozdeji, pouziji se jako oznacena zaloha,
    # kdyz autoritativni verdikt chybi.
    authoritative = [r for r in a.auth if r.authoritative]
    later = [r for r in a.auth if not r.authoritative]
    for mech in ("spf", "dkim", "dmarc"):
        vals = [getattr(r, mech) for r in authoritative if getattr(r, mech)]
        fallback = False
        if not vals and mech in ("dkim", "dmarc"):
            vals = [getattr(r, mech) for r in later if getattr(r, mech)]
            fallback = True
        if not vals:
            continue
        worst = max(vals, key=lambda v: _LEVEL_POINTS.get(_AUTH_LEVEL.get(v, ""), 0))
        level = _AUTH_LEVEL.get(worst)
        if level:
            contribs.append(Contribution(
                code=f"{mech}_{worst}", title=mech.upper(),
                text=f"verification result: {worst}"
                     + (" (later verifier - entry gateway did not measure)"
                        if fallback else ""),
                level=level, points=_LEVEL_POINTS[level]))

    for f in a.findings:
        contribs.append(Contribution(
            code=f.code, title=f.title, text=f.text, level=f.level,
            points=_LEVEL_POINTS.get(f.level, 1)))

    points = sum(c.points for c in contribs)
    # Nejsilnejsi signal nahoru - analytik pri triazi cte shora dolu a chce
    # videt nejhorsi vec prvni. Stabilni razeni zachova poradi v ramci pasma.
    contribs.sort(key=lambda c: c.points, reverse=True)
    return Score(points=points, band=_band(points), contributions=tuple(contribs))
