"""Cesta doruceni z Received hlavicek (signal A3).

Kazdy server po ceste PRIDAVA Received nahoru - v hlavickach je tedy cesta
odzadu. Tady ji obracime (puvod prvni) a redukujeme na citelne hopy:
kdo predal (from), komu (by), kdy. Retez je DUVERYHODNY jen od nasich bran
dolu - spodni (nejstarsi) hopy si utocnik mohl vymyslet; proto se cesta
zobrazuje jako fakta a neskoruje se.

Opakovane identicke hopy (Exchange interni preposilani tymz parem serveru)
se slucuji s pocitadlem - 8x tentyz radek analytikovi nic nerekne.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

_FROM_RE = re.compile(r"\bfrom\s+([^\s(;]+)(?:\s*\(([^)]*)\))?", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s;(]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Hop:
    from_host: str                  # kdo predal ("" u lokalnich zapisu)
    from_info: str                  # obsah zavorky - typicky PTR/[IP]
    by_host: str                    # kdo prijal
    when: str                       # ISO-8601 z casti za ';', nebo ""
    count: int = 1                  # kolik identickych hopu je slouceno


def parse_chain(values) -> tuple[Hop, ...]:
    """Received hlavicky (poradi jako ve zprave, nejnovejsi prvni) -> hopy
    v poradi doruceni (puvod prvni)."""
    hops: list[Hop] = []
    for raw in reversed([str(v) for v in values or []]):
        clause, _, ts = raw.rpartition(";")
        if not clause:
            clause, ts = raw, ""
        f = _FROM_RE.search(clause)
        b = _BY_RE.search(clause)
        when = ""
        try:
            when = parsedate_to_datetime(ts.strip()).isoformat() if ts.strip() else ""
        except (ValueError, TypeError):
            pass
        hop = Hop(from_host=f.group(1) if f else "",
                  from_info=(f.group(2) or "").strip() if f else "",
                  by_host=b.group(1) if b else "", when=when)
        prev = hops[-1] if hops else None
        if prev and (prev.from_host, prev.by_host) == (hop.from_host, hop.by_host):
            hops[-1] = Hop(prev.from_host, prev.from_info, prev.by_host,
                           hop.when or prev.when, prev.count + 1)
        else:
            hops.append(hop)
    return tuple(hops)
