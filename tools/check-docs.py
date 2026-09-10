#!/usr/bin/env python3
"""Kontrola, ze docs/ odpovida kodu.

    python3 tools/check-docs.py

Overuje, ze v dokumentaci nechybi zadny endpoint, chybovy kod, stav
rozbaleni ani promenna prostredi, ze sedi pocty radku a testu a ze
nikam nevede mrtvy odkaz. Vraci nenulovy kod, kdyz neco nesedi -
da se povesit do CI.
"""
import pathlib, re, subprocess, sys

KOREN = pathlib.Path(__file__).resolve().parent.parent
kod = {p.name: p.read_text() for p in (KOREN / "soc_api").glob("*.py")}
docs = {p.name: p.read_text() for p in
        list((KOREN / "docs").glob("*.md")) + [KOREN / "README.md"]}
vse = "\n".join(docs.values())
chyby = []


def zkontroluj(nazev, chybejici):
    if chybejici:
        chyby.append(f"{nazev}: {', '.join(map(str, chybejici))}")
    print(f"  [{'OK' if not chybejici else '!!'}] {nazev}")


zkontroluj("endpointy", [e for e in re.findall(r'@app\.(?:get|post)\("([^"]+)"\)', kod["app.py"])
                         if e.replace("<sha256>", "{sha256}") not in vse])
zkontroluj("chybove kody", [e for e in sorted(
    set(re.findall(r'"error":\s*"(\w+)"', kod["app.py"]))
    | set(re.findall(r'AuthError\(\d+,\s*"(\w+)"', kod["auth.py"]))) if e not in vse])
zkontroluj("extraction.status", [x for x in sorted(
    set(re.findall(r'Result\("(\w+)"', kod["extract.py"]))) if x not in vse])
zkontroluj("promenne prostredi", [e for e in sorted(
    set(re.findall(r'environ\.get\("(\w+)"', kod["config.py"]))) if f"`{e}`" not in vse])

radky = {p.name: len(p.read_text().splitlines()) for p in (KOREN / "soc_api").glob("*.py")}
zkontroluj("pocty radku", [f"{j}: docs {m.group(1)} vs {n}" for j, n in radky.items()
                           if (m := re.search(rf"{re.escape(j)}\s+(\d+)", docs["kod.md"]))
                           and int(m.group(1)) != n])

sber = subprocess.run([sys.executable, "-m", "pytest", "-q", "--collect-only"],
                      capture_output=True, text=True, cwd=KOREN).stdout
behu = len([l for l in sber.splitlines() if "::" in l])
m = re.search(r"\((\d+) běhů", docs["kod.md"])
zkontroluj("pocet testu", [] if m and int(m.group(1)) == behu
           else [f"docs {m.group(1) if m else '?'} vs {behu}"])

mrtve = []
for jm, txt in docs.items():
    base = KOREN / "docs" if jm != "README.md" else KOREN
    for m in re.finditer(r"\[[^\]]+\]\((?!https?:)([^)#]+)", txt):
        if not (base / m.group(1)).resolve().exists():
            mrtve.append(f"{jm} -> {m.group(1)}")
zkontroluj("odkazy", mrtve)

if chyby:
    print("\nNesedi:")
    for c in chyby:
        print("  -", c)
    sys.exit(1)
print("\nDokumentace odpovida kodu.")
