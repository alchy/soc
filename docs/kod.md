# Průvodce kódem

*Kde co leží, kudy teče požadavek a proč je to rozdělené právě takhle.*

Celé to je **809 řádků v pěti modulech**. Malé dost na to, aby se to dalo
přečíst celé; tenhle dokument je mapa, ne náhrada čtení.

```
soc_api/
    config.py      59   konfigurace z prostredi, vychozi hodnoty
    auth.py        78   overeni volajiciho u access-manageru
    storage.py    151   vault: hashe, manifest, access.log vzorku
    extract.py    166   bezpecne rozbaleni ciziho archivu
    app.py        342   HTTP vrstva: endpointy, oba logy
    __main__.py    13   spusteni pod waitress
```

## Dělicí čára, na které to stojí

Moduly jsou rozdělené podle **toho, čemu se dá věřit**:

| modul | vstup | důvěra |
|---|---|---|
| `config` | prostředí | provozovatel — věří se |
| `auth` | klíč od klienta | ověřuje se u autority |
| `storage` | jméno souboru, obsah | nedůvěřuje se |
| `extract` | obsah archivu | **nedůvěřuje se vůbec** |
| `app` | HTTP požadavek | nedůvěřuje se |

Proto `extract.py` nikdy nevyhodí výjimku ven a `storage.safe_filename`
nebere z klientova jména nic než holý základ. Kdo tuhle čáru při úpravách
setře, ztratí to hlavní, co ten kód dělá.

## Kudy teče příjem vzorku

`app.upload()` je jediné místo, kde se ty vrstvy potkávají:

```
POST /api/v1/samples
  │
  ├─ app.caller()                 → auth.authenticate()
  │      klic + adresa klienta       → access-manager /v1/whoami
  │      selze → AuthError → 401/403, zapise se do logu
  │
  ├─ storage.receive()            cte po 64 KB, pocita md5/sha1/sha256,
  │                               hlida strop -> docasny soubor ve vaultu
  │
  ├─ kontrola X-Expected-SHA256   nesouhlas → 422, docasny soubor se smaze
  │
  ├─ storage.read_manifest()      uz ho mame? → 200 duplicate,
  │                               original se NEPREPISUJE
  │
  ├─ shutil.move()                docasny soubor → original/<jmeno>
  ├─ storage.log_event()          "upload" do access.log
  ├─ extract.extract()            nikdy nevyhodi vyjimku, vraci Result
  ├─ storage.log_event()          "extract" do access.log
  └─ storage.write_manifest()     atomicky (tmp + os.replace)
                                  → 201 + Location
```

Pořadí není libovolné. **Událost `upload` se zapisuje dřív, než se cokoli
rozbaluje** — kdyby rozbalování spadlo tak, že to nikdo neošetřil, zůstane
v access.log stopa, že vzorek dorazil.

## `config.py`

Nic než konstanty načtené z prostředí. Žádná logika, žádné odvozování.

Za pozornost stojí jediné: **`VAULT` má výchozí hodnotu mimo webroot**
(`/www/soc/vault`, ne `/www/soc/public_html/...`). Kdyby ležel pod
webrootem, byl by každý přijatý vzorek stažitelný z internetu přes statický
web na téže doméně. Komentář to v kódu říká, aby to nikdo „nesjednotil".

## `auth.py`

Ověřuje klíč u access-manageru, který ho vydal — sami o klíčích nic nevíme
a nic si o nich neukládáme.

Dvě věci, které nejsou samozřejmé:

**Přeposílá se adresa klienta.** `_whoami()` posílá `X-Forwarded-For`
s adresou skutečného klienta, takže origin ACL v access-manageru rozhoduje
o odesílateli vzorku, ne o našem serveru. Bez toho by se měřila adresa
serveru a origin ACL by neznamenal nic.

**Cache je klíčovaná otiskem klíče *a* adresou.**

```python
ck = hashlib.sha256(f"{key}|{client_ip}".encode()).hexdigest()
```

Otiskem proto, aby klíč nedržel v paměti čitelně. Adresou proto, aby tentýž
klíč z jiné sítě musel projít origin ACL znovu — bez toho by cache ACL
obcházela. `AM_CACHE_S` je proto ve vteřinách: je to okno, po které přežije
odvolaný klíč.

## `storage.py`

Vault je **obsahově adresovaný**: cesta vzorku je odvozená z jeho sha256,
takže tentýž obsah má vždy tutéž cestu. Odtud plyne idempotence příjmu —
není to vlastnost, kterou by někdo dopisoval, je to důsledek adresování.

```
vault/<sha256[:2]>/<sha256>/
```

Sharding dvěma znaky drží počet položek v adresáři rozumný i po
desetitisících vzorků.

Tři funkce, u kterých záleží na detailu:

- **`receive()`** čte po 64 KB a hashe počítá za pochodu — 50MB vzorek se
  nikdy nedrží celý v paměti. Při překročení stropu se čtení **zastaví hned**,
  ne až na konci.
- **`write_manifest()`** píše přes dočasný soubor a `os.replace()`. Čtenář
  tak nikdy neuvidí poloviční JSON.
- **`safe_filename()`** bere z klientova jména jen `basename`, nahradí
  metaznaky a odstraní vedoucí tečky. Výsledek `"a/b/c/x.zip"` → `"x.zip"`,
  `".bashrc"` → `"bashrc"`.

`access.log` je JSONL — jeden řádek, jedna událost, append. Formát je
záměrně stejný jako auditní stopa access-manageru.

## `extract.py`

Nejcitlivější modul. Rozbaluje se **cizí, záměrně škodlivý archiv**, takže
každá položka je tvrzení útočníka, ne fakt.

**`extract()` nikdy nevyhodí výjimku.** Vrací `Result` se stavem. To je
záměr: selhání rozbalení není selhání příjmu a originál je uložený tak jako
tak.

Čtyři obrany:

```python
def _safe_target(dest, name):        # cesta mimo cilovy adresar
    target = (dest / name).resolve()
    target.relative_to(dest.resolve())   # ValueError → None
```

Kontroluje se **výsledná cesta po `resolve()`**, ne řetězec. Řetězcové
kontroly na `..` obchází kdejaká kombinace oddělovačů a symlinků.

```python
def _budget_exceeded(total, count, original_size):
    # celkova velikost | pocet polozek | pomer k originalu
```

Tři **nezávislé** stropy. Bomba obvykle překročí některý z nich dávno před
tím, než dojde místo na disku; nezávislost znamená, že obejít se musí
všechny tři, ne jeden.

Symlinky, hardlinky, zařízení a fify se **přeskakují** — u tarů přes
`member.isfile()`, u zipů přes horní bity `external_attr` (`S_IFLNK`).
Přeskočené položky jdou do `Result.skipped`, takže nezmizí potichu.

`_finish()` nakonec odebere `x` bit ze všeho rozbaleného.

## `app.py`

HTTP vrstva. Nic, co by patřilo jinam, tu není — endpointy volají
`storage`/`extract` a formátují odpověď.

**`resolve_client()` vrací dvojici `(adresa, věří se hlavičce?)`**, ne jen
adresu. Ten druhý prvek existuje kvůli diagnostice: když `trusted_proxy`
vyjde `False`, jde do access-manageru adresa proxy místo klienta a origin
ACL přestane rozlišovat kohokoli — aniž by cokoli spadlo. Proto to u
každého odmítnutí končí v logu:

```json
{"event":"auth_denied","peer":"192.0.2.10","client_ip":"2001:db8::55",
 "trusted_proxy":true,"error":"origin_denied"}
```

**Jedno místo, kde se dá snadno udělat chyba:** na `request.files` se smí
sáhnout **jen u skutečného multipartu**.

```python
ctype = (request.content_type or "").lower()
if ctype.startswith("multipart/form-data") and "file" in request.files:
```

Werkzeug parsuje formulář lazy — až při prvním přístupu k `files`/`form` —
a tím vyčerpá `request.stream`. Bez té podmínky by u `curl --data-binary`
(posílá `x-www-form-urlencoded`) došlo do vaultu prázdné tělo. Tahle chyba
tam byla a je opravená; nevracejte ji.

**Dva logy, každý jinam.** Provozní události (`starting`, `auth_denied`)
jdou přes `log()` na `stdout`/`stderr` — běžný provoz na stdout, potíže na
stderr, takže `grep stderr` funguje jako triáž. Odmítnutý požadavek není
chyba procesu, služba se právě zachovala správně.

Vedle toho `@app.after_request` píše **access log** do souboru
(`RotatingFileHandler`, adresář z `SOC_LOG_DIR`, v kontejneru namontovaný
z hostitele). Jeden řádek na požadavek. Rotace je vlastní, ne logrotate —
v kontejneru žádný neběží a na hostiteli by musel umět dát službě vědět.

Identita a předmět požadavku se do něj dostanou přes `flask.g`: `caller()`
ukládá `component`/`key_id`, endpointy `sha256`/`outcome`. Pole, která
nedávají smysl, se **nepíšou** — prázdná hodnota by předstírala, že se
měřila a nic nevyšla.

## Testy

17 testů, běží bez sítě i bez access-manageru.

```
tests/test_extract.py    obrany rozbalovaci vrstvy
tests/test_storage.py    obsahove adresovani, hashe, access.log
```

Test je pojmenovaný tím, co tvrdí (`test_zip_slip_nezapise_ven`), ne tím,
kterou funkci volá. Když přidáváte obranu, přidejte test, který ji **poruší
při odstranění** — ne test, který jen projde kódem.

Co testy **nepokrývají**: HTTP vrstvu a `auth.py` (chtělo by to běžící
access-manager nebo jeho atrapu). Když se do nich pustíte, dělejte to přes
`app.test_client()` a `auth._whoami` podstrčené monkeypatchem.

## Kam sáhnout, když přidáváte analyzátor

`state` v manifestu a endpoint `/analysis` jsou připravené místo:

```python
"state": "extracted" | "received",
"analysis": {"state": "pending"},
```

Analyzátor patří **mimo požadavek** — příjem nesmí čekat na analýzu. Jeho
výsledek se zapíše do `analysis` v manifestu (`storage.write_manifest`) a do
`access.log` jako další druh události.

Klienti se přitom měnit nemusí: přidat *hodnotu* do existujícího pole je
zpětně kompatibilní, přidat *pole* taky. Odebrat ne.
