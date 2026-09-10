# Příručka pro autora klienta

*Píšete nástroj, který bude posílat vzorky. Tenhle dokument je z vaší strany
drátu — co potřebujete vědět, co vám server neodpustí a co naopak odpustí rád.*

Tvary odpovědí do posledního pole jsou v [api.md](api.md); tady je to, co
z nich plyne pro návrh klienta.

## Co potřebujete od provozovatele

| | |
|---|---|
| **URL** | `https://<doména>/api/v1` |
| **aplikační klíč** | `am_k1_…`, vydá se **právě jednou** |
| **povolený rozsah adres** | odkud smíte posílat |

Klíč patří do prostředí nebo secret storu, nikdy do gitu ani do příkazové
řádky (ta je vidět v `ps`). Když se ztratí, nevzpomíná se — provozovatel ho
odvolá a vydá nový.

**Rozsah adres je druhý faktor.** Klíč vynesený mimo povolené sítě je
bezcenný, ale platí to i obráceně: až se vaše odchozí IP změní (nové NAT,
jiná lokalita, VPN), přestane klíč fungovat a dostanete `403 origin_denied`.
Není to porucha klíče, je to změna adresy — řekněte si o rozšíření rozsahu.

## Nejmenší funkční klient

```bash
curl -X POST "$SOC_URL/samples" \
     -H "Authorization: Bearer $SOC_KEY" \
     -H "Content-Type: application/octet-stream" \
     -H "X-Filename: sample.zip" \
     --data-binary @sample.zip
```

> **`Content-Type: application/octet-stream` uveďte.** Bez něj posílá curl
> `application/x-www-form-urlencoded`, server tělo vezme jako formulář
> a dostanete `400 empty_body`. Je to nejčastější chyba prvního pokusu.

Python bez závislostí:

```python
import os, urllib.request

def send(path: str) -> dict:
    with open(path, "rb") as f:
        body = f.read()
    req = urllib.request.Request(
        f"{os.environ['SOC_URL']}/samples", data=body, method="POST",
        headers={"Authorization": f"Bearer {os.environ['SOC_KEY']}",
                 "Content-Type": "application/octet-stream",
                 "X-Filename": os.path.basename(path)})
    with urllib.request.urlopen(req, timeout=300) as r:
        import json
        return json.load(r)
```

## Čtyři vlastnosti, na kterých se dá stavět

### 1. Poslat totéž dvakrát není chyba

Vzorek je adresovaný svým sha256, takže opakované poslání téhož obsahu
**nic nerozbije ani nezduplikuje**. Server vrátí `200` místo `201`
a `"duplicate": true`.

To znamená, že **retry po timeoutu je bezpečný**. Nemusíte řešit, jestli
předchozí pokus prošel — pošlete znovu a podle stavového kódu se dozvíte,
jak to bylo.

```python
try:
    r = send(path)
except TimeoutError:
    r = send(path)          # bezpecne: druhy pokus nevytvori duplikat
```

### 2. Server vám potvrdí, co dorazilo

Pošlete-li `X-Expected-SHA256`, server porovná otisk toho, co skutečně
přijal. Při neshodě vrátí `422 hash_mismatch` a **neuloží nic** — useknutý
přenos se nikdy nezapíše jako platný vzorek.

```python
import hashlib
digest = hashlib.sha256(body).hexdigest()
headers["X-Expected-SHA256"] = digest
```

Stojí to jeden průchod dat a ušetří třídu chyb, která se jinak pozná až při
analýze.

### 3. Neúspěch rozbalení není neúspěch odeslání

Když archiv nejde rozbalit (heslo, poškození, není to archiv), dostanete
pořád **`201`** — originál je uložený, což je to hlavní. Stav je v odpovědi:

```json
{ "state": "received",
  "extraction": { "status": "cannot_decompress",
                  "info": "archiv je chraneny heslem - nelze rozbalit" } }
```

Klient by tohle **neměl brát jako chybu a opakovat**. Opakování dopadne
stejně a jen přibude řádek do access.log.

Rozhodujte podle `extraction.status`, ne podle stavového kódu:

```python
r = send(path)
if r["extraction"]["status"] != "extracted":
    log.warning("ulozeno, ale nerozbaleno: %s", r["extraction"]["info"])
```

### 4. Hesla se nehádají

Když posíláte archiv chráněný heslem (v SOC světě běžná praxe, aby ho AV
po cestě nesežral), počítejte s tím, že se **neotevře**. Uloží se originál
se stavem `cannot_decompress`. Nic se nepokouší heslo uhodnout.

## Chybové stavy a co s nimi

| stav | `error` | co s tím |
|---|---|---|
| `400` | `empty_body` | chybí `Content-Type: application/octet-stream` |
| `401` | `unauthorized` | chybí nebo neplatí klíč — **neopakovat** |
| `403` | `origin_denied` | posíláte z adresy mimo povolený rozsah — **neopakovat**, ozvěte se provozovateli |
| `403` | `wrong_realm` | klíč patří jinému nasazení |
| `413` | `too_large` | vzorek přes limit; `max_bytes` v těle říká kolik |
| `422` | `hash_mismatch` | přenos se poškodil — **opakovat** |
| `502` | `auth_backend_error` | ověřovací služba je dočasně mimo — **opakovat s odstupem** |

Pravidlo: opakovat má smysl u `422`, `502` a síťových chyb. U `401` a `403`
je opakování zbytečné — nic se samo nespraví a jen to plní auditní stopu.

```python
RETRY = {422, 502}

def send_with_retry(path, pokusu=3):
    for i in range(pokusu):
        try:
            return send(path)
        except urllib.error.HTTPError as e:
            if e.code not in RETRY or i == pokusu - 1:
                raise
            time.sleep(2 ** i)
```

## Velikost a časy

- **Strop na vzorek** je konfigurovatelný, u zdejšího nasazení **50 MB**.
  Přesnou hodnotu vrací i tělo chyby `413` v poli `max_bytes`.
- **Timeout klienta dejte velkoryse** (300 s). Server po přijetí ještě
  rozbaluje, takže odpověď na velký archiv nepřijde hned.
- Server nemá frontu — odpověď přichází až po uložení i rozbalení. Až
  přibude analyzátor, poběží mimo požadavek a klienta se to nedotkne.

## Dotazy na už poslané vzorky

```bash
# poslednich 20
curl -H "Authorization: Bearer $SOC_KEY" "$SOC_URL/samples?limit=20"

# vcetne access.logu ke kazdemu
curl -H "Authorization: Bearer $SOC_KEY" "$SOC_URL/samples?limit=20&include=events"

# jeden konkretni vzorek
curl -H "Authorization: Bearer $SOC_KEY" "$SOC_URL/samples/$SHA256"
```

`limit` je 1–200, řadí se od nejnovějšího. Bez `include=events` nese záznam
jen `event_count` — sahejte po `include=events` jen když ta data opravdu
zpracováváte, jinak zbytečně tahá vše.

Detail vzorku (`/samples/{sha256}`) vrací manifest **včetně** `events`
a `files`, takže na běžné „co to bylo za vzorek" stačí jeden požadavek.

## Na co se připravit do budoucna

`GET /samples/{sha256}/analysis` dnes vrací `{"state": "pending"}`. Až
přibude analyzátor, budou v `state` další hodnoty (`analyzing`, `done`, …)
a přibudou pole s výsledkem.

**Pište klienta tak, aby ho neznámá hodnota `state` nerozbila** a aby
ignoroval pole, která nezná. Přidání hodnoty do existujícího pole je
plánovaná změna; přidání pole taky. Odebírání ne.

## Než to pustíte do provozu

- [ ] klíč je v prostředí nebo secret storu, ne v gitu ani v `ps`
- [ ] `Content-Type: application/octet-stream`
- [ ] timeout aspoň 300 s
- [ ] retry jen na `422`, `502` a síťové chyby
- [ ] `X-Expected-SHA256` počítáte a posíláte
- [ ] `extraction.status` čtete a nelogujete ho jako chybu odeslání
- [ ] neznámé `state` a neznámá pole klienta nerozbijí
- [ ] víte, ze které odchozí IP posíláte, a je v povoleném rozsahu
