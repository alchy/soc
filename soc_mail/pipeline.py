"""Bezpecne spousteni komponent analyzy - IZOLACE PADU.

Knihovna casem poroste (dalsi detektory, makra, AV, YARA...). Komponentni
system s izolaci padu je proto od zacatku, ne az nас to prekvapi: kdyz jedna
komponenta na pokrivenem vstupu spadne, OHLASI se jako ComponentFailure, ale
ostatni bezi dal. Analytik tak nedostane misto castecne analyzy prazdnou
stranku - a hlavne nedostane falesne "cisto", kdyz nejaka kontrola tise selze.

Komponenta = dvojice (jmeno, thunk), kde thunk je bezargumentova funkce
(closure navazana na svuj vstup) vracici list[Finding]. run() ji spusti
v try/except; vyjimka se promeni na ComponentFailure a nikdy nepropadne ven.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .models import Finding

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ComponentFailure:
    """Jedna komponenta selhala - jmeno + strucny duvod (pro log i UI)."""
    component: str
    error: str


def run(components: Iterable[tuple[str, Callable[[], list[Finding]]]]
        ) -> tuple[list[Finding], list[ComponentFailure]]:
    """Spusti komponenty s izolaci padu. Vraci (findings, failures) - obe
    vzdy, nikdy nevyhodi. Pad jedne komponenty nezastavi ostatni."""
    findings: list[Finding] = []
    failures: list[ComponentFailure] = []
    for name, thunk in components:
        try:
            findings.extend(thunk() or [])
        except Exception as e:  # zamerne siroke: zadna komponenta nesmi shodit celek
            log.warning("soc_mail component %r failed: %s", name, e)
            failures.append(ComponentFailure(name, f"{type(e).__name__}: {e}"))
    return findings, failures
