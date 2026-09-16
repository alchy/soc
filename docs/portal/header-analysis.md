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
| A3 | cesta doručení | řetěz `Received` odspodu | původní IP/hostname, vstupní bod do internetu, HELO vs PTR | zásobník |
| A4 | odesílací software | `X-Mailer`, `User-Agent`, `X-PHP-Originating-Script` | skript na hacknutém webu vs. legitimní klient | **hotovo** |
| A5 | verdikty po cestě | `X-Spam-Flag/Status`, IronPort/Talos, MS `SCL`, `X-Forefront-Antispam-Report` | co si myslely brány na cestě — „second opinion" zdarma | zásobník |
| A6 | časová anomálie | `Date` vs časy v `Received` | zfalšované Date, podezřelé zpoždění | zásobník |
| A7 | technika obsahu | `Content-Type`, `charset`, `Content-Transfer-Encoding` | base64 HTML bez plaintextu = typický spam vzor | zásobník |
| A8 | skutečný příjemce | `To`, `Delivered-To` | komu kampaň mířila | zásobník |

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

- Každá A-funkce = **komponenta knihovny `soc_mail`** (žádný monolit: `msg.py`
  čtení, `defang.py` zneškodnění, `headers.py` hlavičky). Portál jen volá
  a zobrazuje; knihovnu později beze změny převezme orchestrátor.
- `headers.analyze()` vrací **fakta + nálezy** (`Finding(code, text)`), nic
  neskóruje — vážení signálů je práce analytika (a jednou orchestrátoru).
- B poběží mimo vykreslení stránky (latence, limity, klíče) — jako samostatná
  akce s cache, pravděpodobně už v režii orchestrátoru.
