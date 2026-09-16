# Vytěžnost hlaviček — plán a stav

Co všechno jde pro analytika vytěžit z hlaviček zprávy. Fáze **A** = offline
(jen obsah hlaviček, žádná síť) — implementuje `soc_mail/headers.py`. Fáze
**B** = online obohacení přes free-tier API — **odloženo, začne až po
odsouhlasení A**. Vybíráme postupně; tabulky jsou zásobník, ne závazek.

## A — offline signály

| # | Signál | Z čeho | Co řekne analytikovi | Stav |
|---|---|---|---|---|
| A1 | verdikt autentizace SPF/DKIM/DMARC | `Authentication-Results(-Original)`, `Received-SPF` | nejsilnější indikátor spoofingu; badge pass/fail/none za každého ověřovatele | **hotovo** |
| A2 | nesoulad identit | `From` vs `Reply-To` vs `Return-Path` vs doména `Message-ID`; adresa v display-name | klasika podvodů („OpenAI" nad cizí doménou, `reditel@banka.cz <x@evil.ru>`) | **hotovo** |
| A3 | cesta doručení | řetěz `Received` odspodu | původní IP/hostname, vstupní bod do internetu | **hotovo** (fakta — sbalený výpis hopů se sloučením duplicit; neskóruje se, spodek řetězu může být lživý) |
| A4 | odesílací software | `X-Mailer`, `User-Agent`, `X-PHP-Originating-Script` | skript na hacknutém webu vs. legitimní klient | **hotovo** |
| A5 | verdikty po cestě | `X-Spam-Flag/Status`, `X-ThreatScanner-Verdict`, MS `SCL` | co si myslely brány na cestě — „second opinion" zdarma | **hotovo** (spam flag = VYSOKÁ; SCL ≥5 STŘEDNÍ, ≥7 VYSOKÁ) |
| A6 | časová anomálie | `Date` vs časy v `Received` | zfalšované Date, podezřelé zpoždění | **hotovo** (rozdíl >6 h = NÍZKÁ) |
| A7 | technika obsahu | `Content-Type`, `Content-Transfer-Encoding` | base64 HTML bez plaintextu = typický spam vzor | **hotovo** (NÍZKÁ) |
| A8 | skutečný příjemce | `To` | komu kampaň mířila | **hotovo** (fakta) |
| A2+ | Sender ≠ From | `Sender:` | zprávu odeslala jiná doména než autor (kompromitovaný host) | **hotovo** (NÍZKÁ) |
| A2+ | punycode/IDN | doména `From:` | homoglyf značky (`xn--`) | **hotovo** (STŘEDNÍ) |
| A2+ | header injection | duplicitní `From`/`Subject`/`Date` | DKIM replay / injekce | **hotovo** (KRITICKÁ) |
| A4+ | hromadný mailer | `X-Mailer` | PHPMailer/SwiftMailer/… místo klienta | **hotovo** (NÍZKÁ) |
| A5+ | cloudová kategorie | `X-Forefront-Antispam-Report` `CAT:` | verdikt M365 (PHSH/MALW/SPM/BULK) | **hotovo** (dle CAT) |
| — | DMARC politika | `dmarc=… (p=none)` z A-R | doména DMARC nevynucuje, i když „projde" | **hotovo** (INFO) |

**Poučení z autentizovaného podvodu (report beranek@ans.cz):** BEC/fakturační
podvod, kde útočník korektně autentizoval **vlastní throwaway doménu**
(SPF/DKIM/DMARC pass) → samotná autentizace dává 0 = zelená. Statické netextové
signály výše (Sender≠From, PHPMailer, p=none) ho zvednou na **žlutou (pozor)**.
Limit statiky je poctivě žlutá, ne červená: jádro podvodu (značka v předmětu,
žádost o změnu účtu) je **text** a plná jistota žádá **fázi B** (stáří/reputace
domény). Cíl je splněn — přestane se to jevit jako bezpečné.

## B — online obohacení (free-tier; až po odsouhlasení A)

| # | Služba | Na co se ptáme | Free tier / klíč | Poznámka |
|---|---|---|---|---|
| B1 | DNS (přímý dotaz) | SPF/DMARC záznam, MX, PTR odesílací IP | bez limitu, bez klíče | `dnspython`; nejlevnější první krok |
| B2 | RDAP (rdap.org) | stáří domény, registrátor; vlastník IP/ASN | zdarma, bez klíče | doména stará 3 dny = red flag |
| B3 | AbuseIPDB | abuse skóre IP | 1 000/den, klíč | komunitní reputace |
| B4 | VirusTotal v3 | reputace domény/IP/URL | 4/min, 500/den, klíč | široké pokrytí, těsný limit |
| B5 | abuse.ch URLhaus/ThreatFox | URL proti blacklistu kampaní | zdarma, auth-key | známé kampaně |
| B6 | ip-api.com / ipinfo.io | geolokace + ASN | 45/min bez klíče / 50k měs. | geografický nesmysl odesílatele |
| B7 | DNSBL (Spamhaus zen…) | IP na blacklistu? | DNS zdarma, vlastní resolver | přes 8.8.8.8 nefunguje |

## Kdo je pro SPF/DKIM/DMARC autoritativní

Zpráva u nás projde víc ověřovateli (vstupní IronPort `listonos.ans.cz` →
interní Exchange → hybrid → EOP/M365) a každý razítkuje vlastní
`Authentication-Results`. Verdikty ale **nejsou rovnocenné**:

- **SPF** ověřuje připojující se IP proti doméně z envelope MAIL FROM
  (Return-Path). Skutečnou IP odesílatele viděla **jen vstupní brána** —
  pozdější ověřovatelé (EOP za hybridem) už měří IP *naší vlastní*
  infrastruktury a jejich SPF je artefakt. Proto se **nikdy neskóruje**.
- **DKIM** je kryptografický podpis — primárně bereme vstupní bránu, verdikt
  pozdějšího ověřovatele slouží jako označená záloha.
- **DMARC** je DNS politika domény z `From:` — fakt zjistitelný odkudkoli;
  u nás ho typicky razítkuje až EOP (IronPort dává `validskip`), proto je
  záloha běžná a legitimní.

Technicky: **autoritativní = `Authentication-Results-Original`** (verdikt
vstupní brány zachovaný hybridem); bez něj nejspodnější AR hlavička (původu
nejblíž). UI značí řádky „rozhodující" vs. „informativní"; skóre bere jen
autoritativní (+ označený fallback pro DKIM/DMARC).

## Scoring (`soc_mail/scoring.py`)

Průhledný součet — žádná černá skříňka. Síla signálu na pětistupňové škále
→ body: **INFO=1, NÍZKÁ=2, STŘEDNÍ=3, VYSOKÁ=4, KRITICKÁ=6** (slabý signál
je pořád signál; kritická vyčnívá záměrně). Autentizace se počítá jako
**nejhorší výsledek mechanismu napříč ověřovateli** (útočníkovi stačí projít
jednou): fail/permerror=VYSOKÁ, softfail=STŘEDNÍ, none=NÍZKÁ, neutral=INFO.
Semafor celku: **0 = zelená**, 1–5 = **žlutá**, **6+ = červená**. Skóre se
vrací s rozpadem na příspěvky (`Contribution` s kategorií pro UI), takže
analytik vždy vidí *proč*. Váhy na jednom místě (`_LEVEL_POINTS`,
`_AUTH_LEVEL`, prahy `_BAND_*`). Až přibudou další zdroje (tělo, přílohy,
fáze B), přidají se `score_*` funkce a celek zůstane součtem — kontrakt
`Score` se nemění.

V UI je každý signál **celošířkový řádek** `SEVERITA · kategorie · popis ·
+body` obarvený podle severity; detail ověřovatelů a surová fakta
(From/Reply-To/Return-Path/Message-ID/X-Mailer) jsou sbalené pod signály,
aby pohled nebyl fragmentovaný.

## Architektura

- Knihovna `soc_mail` je **víc malých komponent, ne monolit**: `models.py`
  (sdílené typy), `msg.py` (čtení .msg), `defang.py` (zneškodnění), `received.py`
  (cesta doručení), `headers.py` (parsování hlaviček + orchestrace), `detectors.py`
  (registr detektorů signálů), `scoring.py`. Portál jen volá a zobrazuje;
  knihovnu později beze změny převezme orchestrátor.
- **Přidat signál = napsat funkci `(ctx) -> list[Finding]` a zapsat ji do
  `detectors.DETECTORS`.** `headers.analyze()` se nemění — tím knihovna neroste
  do jednoho velkého `analyze()`.
- `headers.analyze()` vrací **fakta + nálezy** (`Finding`), nic neskóruje —
  vážení signálů je práce analytika (a jednou orchestrátoru).
- **Skóre je nekalibrovaná heuristika, ne měřená pravděpodobnost** (viz odstavec
  výše): slouží k řazení a upozornění, ne jako verdikt; váhy se doladí, až budou
  triažované vzorky. Signály se zobrazují seřazené podle síly (nejhorší nahoře).
- **Defang není bezpečnostní hranice** — tou je sandbox iframe + CSP. Defang je
  vrstva navíc pro čitelnost/copy-paste a nepokrývá všechny obcházky.
- B poběží mimo vykreslení stránky (latence, limity, klíče) — jako samostatná
  akce s cache, pravděpodobně už v režii orchestrátoru.
