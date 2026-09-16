"""VBA/XLM makra v Office prilohe (olevba) - staticky, makro NIKDY nespusti.

Skok od "je makro-dokument" (podle pripony, attachments.py) k "auto-spoustene
makro vola Shell()". olevba (oletools) dokument jen ROZPARSUJE (OLE/OOXML).

Pozn. k zavislosti: oletools je fakticky vzdy pritomny - tahne ho tranzitivne
uz extract-msg (pres RTFDE), coz je jadro soc_mail. olevba (tezky submodul)
se presto importuje LAZY az tady - at se nenacita pri kazdem `import soc_mail`
a at je hranice komponenty jasna. IZOLACE PADU (pipeline.run) chrani pred
pokrivenym dokumentem, ktery olevba shodi, a je pripravena i na budouci
OPRAVDU volitelne komponenty (ClamAV/YARA), ktere v danem kontejneru chybet
mohou - ty pak jen ohlasi ComponentFailure.
"""
from __future__ import annotations

from .models import Finding

_MAX_BYTES = 25 * 1024 * 1024   # nad tuto velikost neparsujeme (DoS strop)


def _map_analysis(has_vba: bool, has_xlm: bool, results) -> list[Finding]:
    """Cista mapa vysledku olevba na Findings - testovatelna bez oletools.

    `results` je iterable dvojic/n-tic (typ, keyword, ...) z analyze_macros;
    typy olevba: 'AutoExec', 'Suspicious', 'IOC', 'Hex String', 'Base64
    String', 'Dridex String', 'VBA obfuscated Strings'.
    """
    out: list[Finding] = []
    if has_xlm:
        out.append(Finding("xlm_macro", "Macro",
            "contains Excel 4.0 (XLM) macros - almost always malicious today",
            level="critical"))
    rows = [(str(r[0]), str(r[1]) if len(r) > 1 else "") for r in results]
    autoexec = sorted({kw for t, kw in rows if t == "AutoExec"})
    susp = sorted({kw for t, kw in rows if t == "Suspicious"})
    obf = any("obfusc" in t.lower()
              or t in ("Hex String", "Base64 String", "Dridex String")
              for t, _ in rows)
    if autoexec and susp:
        out.append(Finding("macro_autoexec", "Macro",
            f"auto-executing VBA macro ({autoexec[0]}) with a suspicious call "
            f"({susp[0]})", level="critical"))
    elif autoexec:
        out.append(Finding("macro_autoexec", "Macro",
            f"auto-executing VBA macro ({', '.join(autoexec[:3])})", level="high"))
    elif susp:
        out.append(Finding("macro_suspicious", "Macro",
            f"VBA macro with suspicious calls ({', '.join(susp[:3])})", level="high"))
    elif obf:
        out.append(Finding("macro_obfuscation", "Macro",
            "VBA macro contains obfuscated strings", level="high"))
    elif has_vba:
        out.append(Finding("macro_present", "Macro",
            "document contains VBA macros", level="medium"))
    return out


def analyze_macros(name: str, data: bytes) -> list[Finding]:
    """Najde a klasifikuje makra v Office dokumentu.

    Muze VYHODIT (chybejici oletools, pokriveny dokument) - to je zamer:
    volajici ji pousti pres pipeline.run, ktery pad izoluje a ohlasi.
    """
    if not data or len(data) > _MAX_BYTES:
        return []
    from oletools.olevba import VBA_Parser  # lazy: nepovinna zavislost

    vp = VBA_Parser(filename=name or "attachment", data=bytes(data))
    try:
        has_vba = bool(vp.detect_vba_macros())
        try:
            has_xlm = bool(vp.detect_xlm_macros())
        except Exception:
            has_xlm = False
        results = vp.analyze_macros() if has_vba else []
    finally:
        vp.close()
    return _map_analysis(has_vba, has_xlm, results)
