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

## Dvě fáze, ne jedna

Práce klienta se dělí na **dva nezávislé kroky** a stojí za to je oddělit
i v kódu. Míchat je do jednoho volání nejde — a nemá to jít.

```
    FAZE 1: ODEVZDANI                     FAZE 2: SLEDOVANI
    (synchronni, jedno volani)            (asynchronni, ptate se vy)

    POST /samples                         GET /samples/{sha256}/analysis
      ├─ ulozi original                     ├─ pending    jeste se nic nedeje
      ├─ rozbali archiv                     ├─ analyzing  bezi
      └─ vrati sha256  ────────────────►    └─ done       vysledek je k dispozici
                    identita vzorku
```

**Fáze 1 je hotová, když dostanete odpověď.** Vzorek je uložený a rozbalený,
`sha256` v odpovědi je jeho trvalá identita. Tím vaše odpovědnost za doručení
končí — dál už jen čtete.

**Fáze 2 je na vás.** Server nikam nevolá zpět, žádný webhook. Ptáte se sami,
kdykoli se vám hodí — za minutu, za hodinu, nebo vůbec.

Prakticky to znamená, že **odesílací a vyhodnocovací část klienta můžou být
dva různé procesy**. Odesílač si po fázi 1 zapíše `sha256` a skončí; něco
jiného se pak ptá na výsledky. Když se odesílač mezitím restartuje nebo
spadne, o nic nepřijdete — vzorek je uložený a identita známá.

> **Analyzátor zatím neexistuje**, takže fáze 2 dnes vždycky vrátí
> `{"state": "pending"}`. Endpoint i pole jsou ale na svém místě od začátku
> právě proto, aby klient napsaný dnes fungoval beze změny, až analyzátor
> přibude. Viz [Na co se připravit do budoucna](#na-co-se-připravit-do-budoucna).

## Fáze 1: odevzdání

### Nejmenší funkční klient

Přijímá se **jen ZIP** — a musí to potvrdit jméno (`.zip`) i obsah. Cokoli
jiného se uloží, ale nerozbalí.

```bash
curl -X POST "$SOC_URL/samples" \
     -H "Authorization: Bearer $SOC_KEY" \
     -F "file=@sample.zip" \
     -F "filename=sample.zip" \
     -F "password=infected"          # jen kdyz je archiv sifrovany
```

Python bez závislostí navíc:

```python
import json, os, urllib.request

def send(path: str, password: str | None = None) -> dict:
    with open(path, "rb") as f:
        body = f.read()
    fields = {"filename": os.path.basename(path)}
    if password:
        fields["password"] = password
    # multipart slozeny rucne, at to nema zavislosti
    bnd = "----soc" + os.urandom(8).hex()
    parts = []
    for k, v in fields.items():
        parts.append(f'--{bnd}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{bnd}\r\nContent-Disposition: form-data; name="file"; '
                 f'filename="{fields["filename"]}"\r\n'
                 f'Content-Type: application/octet-stream\r\n\r\n'.encode()
                 + body + f"\r\n--{bnd}--\r\n".encode())
    req = urllib.request.Request(
        f"{os.environ['SOC_URL']}/samples", data=b"".join(parts), method="POST",
        headers={"Authorization": f"Bearer {os.environ['SOC_KEY']}",
                 "Content-Type": f"multipart/form-data; boundary={bnd}"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)
```

Kdo má `requests`, má to na tři řádky:

```python
requests.post(f"{URL}/samples", headers={"Authorization": f"Bearer {KEY}"},
              files={"file": open(path, "rb")},
              data={"filename": name, "password": heslo})
```

#### Když se vám s multipartem pracuje hůř

Jde poslat i JSON s obsahem v base64. Naroste o třetinu a musí se celý vejít
do paměti, takže u velkých vzorků volte multipart:

```python
{"filename": "sample.zip", "password": "infected",
 "data": base64.b64encode(body).decode()}
```

Třetí možnost je syrové tělo s `X-Filename` — nejjednodušší pro `curl`, ale
**bez možnosti poslat heslo**. Do hlavičky heslo nepatří: skončilo by v logu
každé proxy po cestě.

### Čtyři vlastnosti, na kterých se dá stavět

#### 1. Poslat totéž dvakrát není chyba

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

#### 2. Server vám potvrdí, co dorazilo

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

#### 3. Neúspěch rozbalení není neúspěch odeslání

Když archiv nejde rozbalit (heslo, poškození, není to archiv), dostanete
pořád **`201`** — originál je uložený, což je to hlavní. Stav je v odpovědi:

```json
{ "state": "received",
  "extraction": { "status": "password_required", "format": "zip",
                  "encrypted": true,
                  "info": "archiv je sifrovany, heslo nebylo v pozadavku" } }
```

Klient by většinu z nich **neměl brát jako chybu a opakovat** — opakování
dopadne stejně a jen přibude řádek do access.log. Jediná výjimka je
`password_required`: tam opakování s heslem smysl má (viz bod 4).

Rozhodujte podle `extraction.status`, ne podle stavového kódu:

```python
r = send(path)
if r["extraction"]["status"] != "extracted":
    log.warning("ulozeno, ale nerozbaleno: %s", r["extraction"]["info"])
```

#### 4. Heslo se posílá, nehádá

Posíláte-li archiv chráněný heslem (v SOC světě běžná praxe, aby ho AV po
cestě nesežral), **pošlete heslo v poli `password`**. Nic se nepokouší
uhodnout „infected" ani nic jiného.

Funguje staré ZipCrypto i AES-256 (to, co vyrábí 7-Zip a WinRAR).

Když heslo zapomenete, není to k ničemu ztracené: vzorek se uloží se stavem
`password_required` a **stačí ho poslat znovu s heslem** — server ho
dorozbalí, i když je to jinak duplicita.

```python
r = send(path)
if r["extraction"]["status"] == "password_required":
    r = send(path, password=heslo)      # dorozbali se, vrati 200
```

### Chybové stavy a co s nimi

| stav | `error` | co s tím |
|---|---|---|
| `400` | `empty_body` | u syrového těla chybí `Content-Type: application/octet-stream` |
| `400` | `bad_request` | multipart bez pole `file`, nebo vadný JSON / base64 |
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

### Velikost a časy

- **Strop na vzorek** je konfigurovatelný, u zdejšího nasazení **50 MB**.
  Přesnou hodnotu vrací i tělo chyby `413` v poli `max_bytes`.
- **Timeout klienta dejte velkoryse** (300 s). Server po přijetí ještě
  rozbaluje, takže odpověď na velký archiv nepřijde hned.
- Server nemá frontu — odpověď přichází až po uložení i rozbalení. Až
  přibude analyzátor, poběží mimo požadavek a klienta se to nedotkne.

## Fáze 2: sledování analýzy

```bash
curl -H "Authorization: Bearer $SOC_KEY" "$SOC_URL/samples/$SHA256/analysis"
# {"sha256":"…","state":"pending"}
```

Server **nevolá zpět**. Žádný webhook, žádná fronta — ptáte se vy.

### Jak se ptát

```python
import time

def cekej_na_analyzu(sha256, limit_s=3600):
    """Vraci vysledek, nebo None kdyz to trvá dele nez limit."""
    interval, celkem = 30, 0
    while celkem < limit_s:
        stav = get(f"/samples/{sha256}/analysis")
        if stav["state"] == "done":
            return stav
        if stav["state"] == "failed":          # az takovy stav pribude
            return stav
        time.sleep(interval)
        celkem += interval
        interval = min(interval * 2, 300)      # backoff do 5 minut
    return None
```

Tři věci, které z toho dělají slušného klienta:

- **Backoff.** Ptát se každou vteřinu nic neurychlí. Začněte na desítkách
  vteřin a interval prodlužujte.
- **Strop.** Mějte hranici, po které to vzdáte a řeknete to člověku. Vzorek
  se neztratí, jen na něj nikdo nečeká.
- **Neznámý stav neznamená chybu.** Až přibude analyzátor, přibudou hodnoty
  v `state`. Klient, který na neznámou hodnotu spadne, se rozbije při první
  změně na serveru.

### Co je vedle stavu k dispozici hned

Na tyhle věci čekat nemusíte — jsou hotové ve fázi 1:

```bash
curl -H "Authorization: Bearer $SOC_KEY" "$SOC_URL/samples/$SHA256"
# manifest + events (access.log) + files (rozbalene soubory s hashi)

curl -H "Authorization: Bearer $SOC_KEY" "$SOC_URL/samples/$SHA256/files"
# co bylo v archivu, kazdy soubor s vlastnim sha256
```

### Dotazy na už poslané vzorky

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

**Fáze 1 (odevzdání):**

- [ ] klíč je v prostředí nebo secret storu, ne v gitu ani v `ps`
- [ ] posíláte `.zip` (jiný formát se uloží, ale nerozbalí)
- [ ] heslo dáváte do pole `password`, ne do hlavičky
- [ ] u syrového těla `Content-Type: application/octet-stream`
- [ ] timeout aspoň 300 s
- [ ] retry jen na `422`, `502` a síťové chyby
- [ ] `X-Expected-SHA256` počítáte a posíláte
- [ ] `extraction.status` čtete a nelogujete ho jako chybu odeslání
- [ ] na `password_required` umíte poslat znovu s heslem
- [ ] víte, ze které odchozí IP posíláte, a je v povoleném rozsahu
- [ ] `sha256` z odpovědi si ukládáte — je to jediná identita vzorku

**Fáze 2 (sledování):**

- [ ] ptáte se s backoffem, ne v těsné smyčce
- [ ] máte strop, po kterém to vzdáte a řeknete to člověku
- [ ] neznámá hodnota `state` klienta nerozbije
- [ ] neznámá pole v odpovědi klienta nerozbijí
