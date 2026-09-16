"""Defanging - zneskodneni URL v zobrazovanem obsahu (SOC konvence).

`https://evil.com/x` -> `hxxps://evil[.]com/x`: odkaz zustane citelny pro
analytika, ale neda se omylem prokliknout ani ho prohlizec/klient neudela
aktivnim. Dulezite i pro copy-paste - defangovany tvar se neda vlozit do
adresniho radku bez vedome opravy.

Proc to CSP samo neresi: sandbox+CSP v iframe blokuje skripty a nacitani
zdroju, ale NE navigaci ramu samotneho - klik na <a href> by obsah ramu
presmeroval na server utocnika (= odchozi request z analytikova prohlizece).
Proto se `href` odstranuje a cil se ukazuje jen jako defangovany text.

Knihovna vraci data, neresi HTTP ani sablony (viz soc_mail.__init__).
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup, Comment, Doctype, NavigableString

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\)\]]+", re.IGNORECASE)

# Obsah techto elementu se nedefanguje: neni to text pro cloveka a zasah by
# rozbil vzhled. Aktivni obsah v nich zneskodnuje CSP + odstraneni <script>.
_SKIP_PARENTS = frozenset({"style", "script", "title"})


def _defang_url(url: str) -> str:
    scheme, _, rest = url.partition("://")
    host, sep, tail = rest.partition("/")
    return (scheme.lower().replace("tt", "xx") + "://"
            + host.replace(".", "[.]") + sep + tail)


def defang_text(text: str) -> str:
    """Defanguje vsechny http(s) URL v plaintextu. Ostatni text nemeni."""
    return _URL_RE.sub(lambda m: _defang_url(m.group(0)), text)


def defang_html(data: bytes | str, inject_css: str | None = None) -> str:
    """Vrati HTML bezpecnejsi k ZOBRAZENI (porad nutne servirovat do sandboxu!).

    - <script> a komentare se odstranuji cele (CSP skripty blokuje; komentar
      je skryty obsah, ktery v ctecim boxu nema co delat),
    - <a href> ztraci href a cil se pripoji jako defangovany text v (...),
    - URL ve VSECH atributech (src, background, action, ...) se defanguji -
      CSP jejich nacteni sice blokuje, ale defang chrani i copy-paste,
    - URL v textovych uzlech se defanguji,
    - DOCTYPE se normalizuje na HTML5 `html` (identifikator DTD nese URL).

    `inject_css` (volitelne) se vlozi jako <style> na KONEC dokumentu - kaskada
    tak nechava vyhrat volajiciho (s !important prebije i inline styly zpravy).
    Knihovna zadny vzhled nevnucuje; co vlozit, urcuje prezentacni vrstva.

    Bajty dekoduje BeautifulSoup (respektuje <meta charset> zpravy); vystup
    je vzdy utf-8 retezec, takze volajici muze poslat charset s jistotou.
    """
    soup = BeautifulSoup(data, "html.parser")

    for tag in soup.find_all("script"):
        tag.decompose()
    for node in soup.find_all(string=lambda s: isinstance(s, Comment)):
        node.extract()
    for node in soup.contents:
        if isinstance(node, Doctype):
            node.replace_with(Doctype("html"))
            break

    for a in soup.find_all("a"):
        url = a.get("href") or ""
        if a.has_attr("href"):
            del a["href"]
        if url.lower().startswith(("http://", "https://")):
            a.append(NavigableString(f" ({_defang_url(url)})"))

    for tag in soup.find_all(True):
        for attr, val in list(tag.attrs.items()):
            if isinstance(val, str):
                tag.attrs[attr] = defang_text(val)

    for node in soup.find_all(string=True):
        if type(node) is not NavigableString:   # Doctype/CData uz jsou vyrizene
            continue
        if node.parent and node.parent.name in _SKIP_PARENTS:
            continue
        fixed = defang_text(str(node))
        if fixed != node:
            node.replace_with(NavigableString(fixed))

    if inject_css:
        style = soup.new_tag("style")
        style.string = inject_css
        (soup.body or soup.html or soup).append(style)

    return str(soup)
