# REST API

*Drátové rozhraní služby: tvary požadavků a odpovědí.*

Základ cesty je `/api/v1`. Všechny odpovědi jsou JSON, včetně chyb — i těch,
které vrací ještě reverzní proxy (viz `error_page` ve vzoru vhostu).

## Autentizace

Každý požadavek kromě `/healthz` nese aplikační klíč realmu:

```http
Authorization: Bearer am_k1_9f3c…
```

Klíč vydává správce realmu v access-manageru při registraci aplikace; server
o něm drží jen sha256 otisk. soc-api si ho ověřuje voláním `GET /v1/whoami`
na access-manageru a výsledek krátce cachuje (`SOC_AM_CACHE_S`, výchozí 30 s)
— odvolání klíče se proto projeví až po vypršení cache.

Kontroly běží v tomto pořadí:

1. **Klíč** — chybějící i neplatný je `401` a žádný jiný rozdíl.
2. **Origin ACL** — adresa klienta mimo rozsahy komponenty je `403`.
   Měří se adresa, kterou soc-api přeposlal v `X-Forwarded-For`, tedy
   **skutečný odesílatel**, ne server, na kterém soc-api běží.
3. **Realm** — klíč z jiného realmu je `403`, i když je platný.

| stav | `error` | kdy |
|---|---|---|
| `401` | `unauthorized` | chybí nebo neplatí klíč |
| `403` | `origin_denied` | adresa není v povolených rozsazích |
| `403` | `wrong_realm` | klíč patří jinému realmu |
| `502` | `auth_backend_error` | access-manager je nedostupný |

Cache je klíčovaná otiskem klíče **i adresou** — tentýž klíč z jiné sítě musí
projít origin ACL znovu.

## `POST /api/v1/samples` — příjem vzorku

Přijímá se **jen ZIP**. Jméno archivu určuje formát a musí ho potvrdit
i obsah — viz [Formát a heslo](#formát-a-heslo) níže.

Požadavek má tři podoby. **Heslo k archivu jde poslat jen v prvních dvou** —
v hlavičce by skončilo v logu každé proxy po cestě.

### multipart/form-data (doporučeno)

```http
POST /api/v1/samples
Authorization: Bearer am_k1_…
Content-Type: multipart/form-data; boundary=…

file=<binarni obsah>       povinne
filename=sample.zip        jinak se vezme z pole `file`
password=infected          jen kdyz je archiv sifrovany
```

```bash
curl -X POST "$SOC_URL/samples" -H "Authorization: Bearer $SOC_KEY" \
     -F "file=@sample.zip" -F "filename=sample.zip" -F "password=infected"
```

### application/json

Pro klienty, kterým se s multipartem pracuje hůř. Obsah je base64, takže
**naroste o třetinu** a musí se celý vejít do paměti — u velkých vzorků
volte multipart.

```json
{ "filename": "sample.zip",
  "password": "infected",
  "data": "UEsDBBQAAAAIA…" }
```

### syrové tělo

Nejjednodušší pro `curl`, ale **bez možnosti poslat heslo**.

```http
POST /api/v1/samples
Content-Type: application/octet-stream
X-Filename: sample.zip
X-Expected-SHA256: 9f61e556…        (nepovinne, u vsech tri podob)

<binarni telo>
```

> `Content-Type: application/octet-stream` uveďte. Bez něj posílá curl
> `x-www-form-urlencoded`, server tělo vezme jako formulář a vrátí
> `400 empty_body`.

`X-Expected-SHA256` je nepovinná kontrola integrity: při neshodě `422`
a **neuloží se nic**.

### Odpovědi

```http
201 Created
Location: /api/v1/samples/9f61e556…
```

```json
{
  "sha256": "9f61e5567859e0aa…",
  "md5": "13e3a854…", "sha1": "f46afde3…",
  "size": 386,
  "filename": "sample.zip",
  "received_at": "2026-09-10T13:08:30+00:00",
  "received_from": "192.0.2.55",
  "received_by": { "component": "socupload", "key_id": "k1",
                   "realm": "soc.example.com" },
  "state": "extracted",
  "extraction": { "status": "extracted", "info": "",
                  "format": "zip", "encrypted": true,
                  "file_count": 3, "total_bytes": 72 },
  "analysis": { "state": "pending" },
  "event_count": 2
}
```

| stav | `error` | kdy |
|---|---|---|
| `201` | — | nový vzorek |
| `200` | — | tentýž obsah už máme; navíc `"duplicate": true` |
| `400` | `bad_request` | multipart bez pole `file`, nebo vadný JSON / base64 |
| `400` | `empty_body` | prázdné tělo |
| `413` | `too_large` | přes `SOC_MAX_UPLOAD` |
| `422` | `hash_mismatch` | přenos neodpovídá `X-Expected-SHA256` |

Duplicita **není chyba**: originál se nepřepisuje (je to tentýž obsah byte za
bytem), ale pokus se zapíše do `access.log`.

**Jedna věc, kterou opakovaný příjem změnit může:** archiv, který čekal na
heslo (`password_required` nebo `bad_password`), se **dorozbalí**, když teď
heslo dorazí. Stav rozbalení je vlastnost vzorku, ne požadavku.

## Formát a heslo

Přijímá se **jen ZIP** a musí to potvrdit obojí:

| | | |
|---|---|---|
| **suffix jména** | `.zip` | tvrzení klienta |
| **magické bajty** | `PK…` | fakt |

Rozdělení není zbytečné — každá kontrola chytí jinou chybu: špatně
pojmenovaný archiv i podvržený obsah. RAR, 7z, gzip, bzip2, xz a tar se
poznají podle hlavičky a odmítnou se **pojmenovaně**, aby klient věděl, co
poslal, místo holého „není to zip".

Heslo umí jen ZIP, protože jiný formát se nepřijímá. Šifrovaný ZIP nese buď
staré ZipCrypto, nebo AES (7-Zip, WinRAR) — **zvládnou se oba**. Heslo se
**nikdy nehádá** a nikam se neukládá ani neloguje.

| `extraction.status` | `state` | význam |
|---|---|---|
| `extracted` | `extracted` | rozbaleno |
| `password_required` | `received` | šifrovaný archiv, heslo nebylo v požadavku |
| `bad_password` | `received` | heslo nesouhlasí |
| `unsupported_format` | `received` | není to `.zip`; `format` říká, co to je |
| `format_mismatch` | `received` | jméno slibuje zip, obsah je něco jiného |
| `corrupt` | `received` | poškozený archiv |
| `cannot_decompress` | `received` | ostatní — důvod v `info` |

`extraction` nese vedle stavu i `format` (co to podle hlavičky je),
`encrypted` (bool), `file_count`, `total_bytes` a případně `skipped`.

**Originál zůstává uložený vždy**, i když rozbalení selže. Návratový kód
příjmu je `201` i tehdy — uložení je to hlavní, rozbalení pohodlí navíc.

## `GET /api/v1/samples` — výpis

```http
GET /api/v1/samples?limit=20&include=events
```

| parametr | výchozí | co dělá |
|---|---|---|
| `limit` | 20 | kolik vzorků, 1–200, od nejnovějšího |
| `include` | — | `events` přiloží ke každému záznamu jeho access.log |

Bez `include=events` nese záznam jen `event_count` — jinak by výpis 200 vzorků
narostl o všechny jejich události.

```json
{ "count": 3, "limit": 3,
  "samples": [
    { "sha256": "0fd24b82…", "filename": "secret.zip", "size": 246,
      "received_at": "…", "state": "received",
      "extraction": { "status": "cannot_decompress", "file_count": 0 },
      "event_count": 2 }
  ] }
```

## `GET /api/v1/samples/{sha256}` — detail

Vrací celý manifest **včetně** `events` (access.log) a `files` (rozbalené
soubory s velikostí a hashem). Samotné čtení se do access.log také zapisuje.

`404 not_found`, pokud vzorek neznáme; `400 bad_request`, pokud sha256 nemá
64 hex znaků.

## `GET /api/v1/samples/{sha256}/events`

```json
{ "sha256": "…", "count": 2, "events": [
    { "t": "…", "event": "upload", "remote_ip": "192.0.2.55",
      "component": "socupload", "key_id": "k1", "realm": "soc.example.com",
      "filename": "sample.zip", "size": 386, "sha256": "…",
      "duplicate": false },
    { "t": "…", "event": "extract", "status": "extracted",
      "file_count": 3, "total_bytes": 72 }
] }
```

Druhy událostí: `upload`, `extract`, `read`.

## `GET /api/v1/samples/{sha256}/files`

```json
{ "sha256": "…",
  "extraction": { "status": "extracted", "file_count": 3, "total_bytes": 72 },
  "count": 3,
  "files": [ { "path": "sub/nested.txt", "size": 15, "sha256": "…" } ] }
```

Cesty jsou relativní ke kořeni rozbaleného obsahu. Každý soubor má vlastní
sha256, aby šel dohledat samostatně.

## `GET /api/v1/samples/{sha256}/analysis`

Druhá fáze práce s API. Příjem (`POST /samples`) je **synchronní** — když
odpoví, je vzorek uložený a rozbalený. Analýza je **asynchronní** a server
nikam nevolá zpět; ptá se klient, kdykoli se mu hodí.

```json
{ "sha256": "…", "state": "pending" }
```

Místo pro analyzátor. `state` je v manifestu od začátku, takže až analyzátor
přibude, přibudou jen **hodnoty** do existujícího pole — klienti se měnit
nemusí. Přidat pole by je rozbilo, přidat hodnotu ne.

## `GET /api/v1/healthz`

Bez klíče. `200` když je vault dostupný, jinak `503`.

```json
{ "status": "ok", "vault": "/www/soc/vault", "vault_writable": true }
```
