# HANDOVER — SOC systém (soc-api / soc-orchestrator / soc-portal)

Předávka stavu pro další instanci. Píše se česky (komentáře kódu i docs jsou
česky; **UI je anglicky** — SOC tým je multilingvální). Datum: 2026-09-16.

> Detailní kontext žije v `docs/` a v auto-memory
> `/www/soc/.claude/projects/-www-soc/memory/` (hlavně `project-soc-portal.md`).
> Tenhle soubor je rozcestník + stav, ne náhrada dokumentace.

---

## 1. Co to je

Monorepo `/www/soc/repo` se **třemi nasazovatelnými komponentami** + jednou
sdílenou knihovnou. Běží jako oddělené procesy/kontejnery (rootless podman,
systemd, EL10), sdílí **jen obsah vaultu**.

| Komponenta | Role | Vault | Běží? | Analytické deps |
|---|---|---|---|---|
| **soc_api** | příjem vzorků od podnikové brány | RW | **ano** (:8095, `/api`) | ne |
| **soc_orchestrator** | analýza pending vzorků → `analysis.json` | RW | **NE (postaveno, nenasazeno)** | **ano (jen tady)** |
| **soc_portal** | čtecí okno SOC analytika | RO | **ano** (:8096, `/portal`) | interim ano → cíl ne |
| `soc_mail` | knihovna analýzy mailu | — | — | importuje orchestrátor (+ zatím portál) |

Vault: `vault/<sha256[:2]>/<sha256>/{manifest.json, access.log, original/, extracted/}`.
`extracted/` = `headers.txt, body.html, body.txt, metadata.json, message.msg, attachments/`.
Obsahově adresované (sha256), neměnné. Zapisovatelé (soc_api, orchestrátor) píšou
**atomicky** (temp + `os.replace`) — čtenáři nikdy nevidí rozepsaný JSON. Tohle je
invariant, který MUSÍ ctít každý zapisovatel.

## 2. Datový tok (LOCKED model)

```
mail → soc_api uloží (extract do vaultu, manifest.analysis.state = "pending")
        → portál HNED zobrazí STATICKÉ soubory (odesílatel/předmět/tělo/hlavičky
          /přílohy) BEZ hodnocení, indikuje "analýza čeká"
        → orchestrátor (smyčka ~1 min) vezme pending → soc_mail → zapíše
          analysis.json (report) + [fáze 2] artefakty (defangované tělo, PDF PNG)
          → state = "done"
        → soc_api servíruje report jako JSON (GET /api/v1/samples/{sha}/analysis)
          portál překryje hodnocení jako HTML (blokový rendering)
```

**Klíč:** analytické závislosti (`soc_mail`, extract-msg, oletools, poppler)
jsou **JEN v orchestrátoru**. Portál i soc_api jsou nakonec jen čtenáři/servírovači
reportu. Portál cílově = RO vault (statika + report) + access-manager (auth),
ŽÁDNÝ analytický kód. Nepřátelský obsah (PDF render) se pitvá v orchestrátoru,
mimo analytikův portál; portál servíruje inertní PNG.

## 3. Prezentační kontrakt — blokový report (`soc_mail/report.py`, `REPORT_SCHEMA=1`)

`analysis.json` = **uspořádaná sekvence typovaných bloků**. Prezentační vrstva
(portál HTML, soc_api JSON) rendruje podle `type`, nezná semantiku analýzy.
**Přidat vizuální prvek = nový typ bloku + jeden renderer**; neznámý typ se
přeskočí (dopředná kompatibilita). Držet slovník malý, sémantický, verzovaný.

Bloky v1: `score{points,band}` · `alert{severity,what,comment,points}` (barevný
box signálu) · `auth{verifiers[]}` · `facts{title,rows[]}` · `delivery_path{hops[]}`
· `message{sender,subject,date,attachments[]}` · `diagnostic{component,error}`.
Rezervované: `body{kind,ref}` · `preview{kind,ref,caption}` (fáze 2 artefaktů).
Nahoře navíc `verdict{points,band}` + `summary{sender,subject,received_at,is_report}`
jako zkratka pro dashboard.

Reálný příklad (malisová `a80d557d…`): `verdict 19/high`, bloky score → message →
7× alert (seřazené nejhorší nahoře) → auth → facts → delivery_path.

## 4. Knihovna `soc_mail` — komponenty (NE monolit)

`models`(leaf: Finding, MailContext) · `msg`(čtení .msg, `office_attachments`) ·
`defang`(zneškodnění URL/HTML — **NENÍ bezpečnostní hranice**, tou je sandbox+CSP) ·
`received`(cesta doručení) · `headers`(parse faktů + orchestrace detektorů) ·
`detectors`(**registr** `(ctx)->list[Finding]`) · `attachments`(riziko podle jména) ·
`macros`(olevba, **lazy import**) · `scoring`(průhledný součet) · `pipeline`(**izolace
pádů**) · `sample`(`analyze_message` — sdílené sestavení) · `report`(blokový kontrakt).

**Jak rozšířit:**
- nový signál z hlaviček → napiš `detect_x(ctx)` v `detectors.py` a přidej do `DETECTORS`,
- nový zdroj signálů (tělo, online) → `score_headers(..., extra_findings=...)`,
- nový vizuální prvek → nový blok v `report.py` + renderer v prezentační vrstvě.

**IZOLACE PÁDŮ (`pipeline.run`):** komponenta = `(jméno, thunk)`; když spadne,
ohlásí se jako `ComponentFailure`, ostatní běží dál. V UI „analyzer unavailable
— analysis is partial" (žádné falešné „čisto"). Komponenty SMĚJÍ vyhazovat; runner
je izoluje.

**Scoring je NEKALIBROVANÁ heuristika** (ne měřená pravděpodobnost): 5 stupňů
INFO/LOW/MEDIUM/HIGH/CRITICAL → body 1/2/3/4/6; pásma 0=zelená, 1–5=žlutá, 6+=červená.
Autentizace se boduje **jen z autoritativního ověřovatele** = `Authentication-Results-Original`
(vstupní brána, jediná viděla skutečnou IP); **SPF pozdějších ověřovatelů se NIKDY
neboduje** (artefakt hybridu — jinak bychom trestali legitimní poštu). Váhy se doladí,
až budou triažované vzorky.

**Poučení beranek@ans.cz (BEC/fakturační podvod):** útočník korektně autentizoval
VLASTNÍ throwaway doménu (SPF/DKIM/DMARC pass) → autentizace 0 = zelená. Statické
netextové signály (Sender≠From, PHPMailer, p=none) zvednou na 5/žlutá. Poctivý strop
statiky je **žlutá, ne červená** — jádro podvodu je text a plná jistota žádá fázi B.

Pokryté statické signály: A1–A8 (viz `docs/portal/header-analysis.md`) + Sender≠From,
punycode/IDN, header injection (duplicitní From/Subject/Date), hromadný mailer,
cloud `CAT:`, DMARC `p=none`, riziko příloh podle jména (exec/dvojitá přípona/SVG/
makro/archiv), olevba makra.

## 5. Orchestrátor (`soc_orchestrator/`) — POSTAVENO, NENASAZENO

Trigger = **`manifest.analysis.state`** (soc_api ho při příjmu nastaví na `pending`,
viz `soc_api/app.py:312`). Jednoduchá smyčka: `reclaim → zpracuj pending → heartbeat
→ sleep 60s`. Stavový automat: `pending → running`(claim, atomicky) `→ done|error`;
`running` déle než timeout (spadlý worker) → reclaim zpět na `pending`.
- pád procesu → **restart kontejneru** (systemd `Restart=always`),
- zaseknutí → **per-vzorek timeout** (`signal.alarm`) + **heartbeat healthcheck**,
- `SIGTERM` ukončí smyčku čistě po aktuálním vzorku.
- `runner` používá sdílené `soc_mail.analyze_message` + `build_report` (žádná duplikace).

Spuštění/test: `python -m soc_orchestrator [--once] [--dry-run]`.
**Dry-run proti živému vaultu je ověřený a NIC nezapisuje** — bezpečný způsob, jak
testovat, aniž mutuješ produkční vault. POZOR: bez `--dry-run` orchestrátor mutuje
manifesty a píše `analysis.json` do živého vaultu.

Container builder (dle CONTAINER-RULEZ, `<s>=soc-orchestrator`): `Dockerfile.orchestrator`
(RW vault, heartbeat HEALTHCHECK, **žádný EXPOSE** — není to web), `deploy/
container-build-soc-orchestrator.sh`, `deploy/entrypoint-soc-orchestrator.sh`.

## 6. Portál — INTERIM stav

Dnes portál **analyzuje sám za běhu** (volá `soc_mail` v `routes_samples.py`) — to je
**dočasné**. Cílově se přepne na **čtení `analysis.json` reportu** a analytický kód
(+ oletools v `Dockerfile.portal`) se odstraní. Detail už izoluje makra jako komponentu
a hlásí selhání („analyzer unavailable"). Dashboard řádek = skóre + reportovaná zpráva.

## 7. STAV A DALŠÍ KROKY (pořadí)

Vše je **commitnuté** (viz `git log`), strom čistý. 162 testů zelených.
Běží: soc-api, soc-portal, access-manager. **Orchestrátor NEBĚŽÍ** (jen kód).

1. **Napojit portál na report** — blokové renderery (Jinja makra podle `type`) +
   „analýza čeká" indikátor. Pak odstranit z portálu on-demand analýzu + oletools
   (interim z commitu `d763546`).
2. **Fáze prezentačních artefaktů orchestrátoru** — defangované tělo + PDF náhled
   (`pdftoppm`, první stránka, strop DPI/rozměrů, timeout, no-JS/no-net) → `body`/
   `preview` bloky. Tím padá „poppler v portálu".
3. **soc_api `/analysis`** — dnes placeholder (`docs/api.md:238`), naplnit: načíst
   `analysis.json` a vrátit jako JSON. soc_api NIC nepočítá, jen servíruje.
4. **Deploy orchestrátoru** — chybí run wrapper + install skript + systemd unit
   (`Restart=always`) + RW mount vaultu (`:z`, jako soc-api). Vyžaduje sudo (systemd).

## 8. Build / test / provoz

- Prostředí je **efemérní** — v čerstvé session není venv:
  `cd /www/soc/repo && python -m venv .venv && .venv/bin/pip install -e . && .venv/bin/pip install pytest`
  (`oletools` se přitáhne s `extract-msg` tranzitivně přes RTFDE).
- Testy: `.venv/bin/python -m pytest tests/ -q` (mailová část hermetická přes
  `tests/fixtures/*.headers.txt`; testy s vaultem jsou integrační, skipnou bez vaultu).
- Hlídač shody docs↔kód: `.venv/bin/python tools/check-docs.py`.
- Build obrazů: `deploy/container-build-<s>.sh` (soc-api / portal / soc-orchestrator).
- **Obrazy jsou zastaralé** vůči HEAD: portál `localhost/soc-portal:latest` je z ~2h,
  ale předchází části práce; před nasazením **rebuild**. soc-api obraz je 5 dní starý.
- Systemd restart vyžaduje **sudo s heslem** (mám jen nepřihlášené sudo) — restart
  dělá jindrich přes `! sudo systemctl restart <s>-container`.

## 9. Gotchas & konvence

- **CONTAINER-RULEZ.md** (kořen repa) = normativní standard pro všechny rootless-podman
  služby. Každý deploy/build/install/entrypoint skript nese `<s>` VŽDY.
- **access-manager** klíč portálu je `k6` (k5 přestal platit 2026-09-16 → 401 →
  crash-loop → nginx 502). Secrets v `/etc/sysconfig/soc-portal-container` (mode 600,
  owner soc — Claude smí číst/psát). Unit auto-restart čte EnvironmentFile každý pokus
  → oprava klíče NEpotřebuje ruční restart.
- `oletools` je tranzitivní dep `extract-msg` (přes RTFDE) — je všude, kde je `extract-msg`.
  Tvrzení „soc_mail jde importovat bez oletools" je NEPRAVDIVÉ (extract-msg ho potřebuje).
- SELinux **Permissive** na hostu; vault mount soc-api je `:z` (sdílený label).
- nginx: přidání JAKÉHOKOLI `add_header` do `location /portal/` tiše zahodí všech 6
  server-level bezpečnostních hlaviček (all-or-nothing). Živý conf je root-owned.
- Auto-memory je zdroj pravdy o rozhodnutích; před doporučením ověř, že jmenovaný
  soubor/flag pořád existuje.

## 10. Mapa klíčových souborů

```
soc_mail/           knihovna analýzy (viz §4)
soc_orchestrator/   3. komponenta (config/state/runner/vault_rw/__main__)
soc_api/            příjem (Flask; app.py, storage.py) — BEŽÍ, needit bez nutnosti
soc_portal/         portál (web/{app,routes_*,templates,static}, auth/, vault_reader)
Dockerfile[.portal|.orchestrator]   obrazy
deploy/             build/run/entrypoint/install skripty + systemd unity + nginx .example
docs/               api.md, klient.md, nasazeni.md, kod.md, CONTAINER (…), portal/{implementation,header-analysis}.md
tools/check-docs.py hlídač shody docs↔kód
tests/{,mail,portal,orchestrator}/  pytest
```
