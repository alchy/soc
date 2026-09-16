"""Staticka rizika priloh - jen ze JMENA a typu, zadny obsah zpravy.

Kde jinde zije malware nez v priloze. Ze jmena souboru jde bez otevirani
rozpoznat: spustitelne/skriptove pripony, dvojita pripona (faktura.pdf.exe),
SVG (muze nest JavaScript), makro-office. ZADNA analyza obsahu - to je uz
prace pro sandbox/render, ne staticky nazev.

Vstup jsou MailAttachment (jmeno + velikost) z ParsedMessage; vystup Findings
do stejneho scoringu jako hlavicky.
"""
from __future__ import annotations

from collections.abc import Iterable

from .models import Finding
from .msg import MailAttachment

# spustitelne / skriptove pripony - primy kod
_EXEC = {".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".bat", ".cmd",
         ".ps1", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
         ".lnk", ".jar", ".reg", ".inf"}
# makro-schopne office dokumenty
_MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}
# archivy / disk image - muzou skryvat payload (nebo obejit skener)
_ARCHIVE = {".zip", ".rar", ".7z", ".gz", ".tar", ".iso", ".img", ".vhd", ".cab"}
# "navnadove" pripony, ktere se pred spustitelnou pripona snazi vypadat neskodne
_DECOY = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".txt", ".csv",
          ".rtf", ".jpg", ".jpeg", ".png", ".gif"}


def _suffixes(name: str) -> list[str]:
    """Vsechny pripony malymi pismeny: 'Faktura.PDF.exe' -> ['.pdf', '.exe']."""
    return ["." + p.lower() for p in name.split(".")[1:]] if "." in name else []


def analyze_attachments(attachments: Iterable[MailAttachment]) -> list[Finding]:
    out: list[Finding] = []
    for att in attachments:
        name = att.name or ""
        sfx = _suffixes(name)
        if not sfx:
            continue
        ext = sfx[-1]

        # Dvojita pripona: 'invoice.pdf.exe' - navnada + skutecny spustitelny typ.
        if len(sfx) >= 2 and sfx[-2] in _DECOY and ext in _EXEC:
            out.append(Finding("double_extension", "Attachment",
                f"{name!r} uses a double extension ({sfx[-2]}{ext}) to masquerade "
                f"as a {sfx[-2].lstrip('.')} file", level="critical"))
            continue

        if ext in _EXEC:
            out.append(Finding("dangerous_attachment", "Attachment",
                f"{name!r} is an executable/script ({ext})", level="critical"))
        elif ext == ".svg":
            out.append(Finding("active_svg", "Attachment",
                f"{name!r} is an SVG - may contain embedded JavaScript", level="high"))
        elif ext in _MACRO:
            out.append(Finding("macro_document", "Attachment",
                f"{name!r} is a macro-enabled document ({ext})", level="high"))
        elif ext in _ARCHIVE:
            out.append(Finding("archive_attachment", "Attachment",
                f"{name!r} is an archive/disk image ({ext}) - may hide a payload",
                level="info"))
    return out
