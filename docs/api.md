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

```http
POST /api/v1/samples
Authorization: Bearer am_k1_…
Content-Type: application/octet-stream
X-Filename: sample.zip
X-Expected-SHA256: 9f61e556…        (nepovinné)

<binární tělo>
```

Přijímá se i `multipart/form-data` s polem `file`; jméno se pak bere z něj.

`X-Expected-SHA256` je nepovinná kontrola integrity. Když se neshodne s tím,
co skutečně dorazilo, vrátí se `422` a **neuloží se nic** — chrání proti
useknutému přenosu.

### Odpovědi

```http
201 Created
Location: /api/v1/samples/9f61e556…
```

```json
{
  "sha256": "9f61e5567859e0aa…",
  "md5": "13e3a8548139204d27d6e8ceeff3c660",
  "sha1": "f46afde3b9e7c6e3cbcf20a23c1fc3a6d0fb0844",
  "size": 386,
  "filename": "sample.zip",
  "received_at": "2026-09-10T13:08:30+00:00",
  "received_from": "192.0.2.55",
  "received_by": { "component": "socupload", "key_id": "k1",
                   "realm": "soc.example.com" },
  "state": "extracted",
  "extraction": { "status": "extracted", "info": "",
                  "file_count": 3, "total_bytes": 72 },
  "analysis": { "state": "pending" },
  "event_count": 2
}
```

| stav | `error` | kdy |
|---|---|---|
| `201` | — | nový vzorek |
| `200` | — | tentýž obsah už máme; navíc `"duplicate": true` |
| `400` | `empty_body` | prázdné tělo |
| `413` | `too_large` | přes `SOC_MAX_UPLOAD` |
| `422` | `hash_mismatch` | přenos neodpovídá `X-Expected-SHA256` |

Duplicita **není chyba**: originál se nepřepisuje (je to tentýž obsah byte za
bytem), ale pokus se zapíše do `access.log`. Kdo poslal totéž znovu, je pro
SOC informace.

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

## Stavy rozbalení

| `extraction.status` | `state` vzorku | význam |
|---|---|---|
| `extracted` | `extracted` | rozbaleno |
| `cannot_decompress` | `received` | nelze rozbalit — důvod v `info` |
| `not_an_archive` | `received` | není zip ani tar; uložen jen originál |
| `corrupt` | `received` | archiv je poškozený |

Přeskočené položky (zip-slip, symlinky, zařízení) jsou v `skipped`, jejich
celkový počet v `skipped_total`. Vypisuje se nejvýš prvních 20 — seznam
deseti tisíc přeskočených položek nikomu nepomůže.

**Originál zůstává uložený vždy**, i když rozbalení selže. Hesla se nehádají.
