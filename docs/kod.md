# Průvodce kódem

*Kde co leží, kudy teče požadavek a proč je to rozdělené právě takhle.*

Celé to je **985 řádků v pěti modulech**. Malé dost na to, aby se to dalo
přečíst celé; tenhle dokument je mapa, ne náhrada čtení.

```
soc_api/
    config.py      63   konfigurace z prostredi, vychozi hodnoty
    auth.py        78   overeni volajiciho u access-manageru
    storage.py    160   vault: hashe, manifest, access.log vzorku
    extract.py    250   bezpecne rozbaleni ZIPu (i sifrovaneho)
    app.py        421   HTTP vrstva: endpointy, oba logy
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

### Formát: dvě kontroly, každá chytí něco jiného

```python
if not ma_zip_suffix(filename):      # tvrzeni klienta
    return Result("unsupported_format", …)
if format_z_obsahu(src) != "zip":    # fakt
    return Result("format_mismatch", …)
```

Přijímá se jen ZIP. `format_z_obsahu()` ale rozpoznává i formáty, které
**nepřijímáme** (rar, 7z, gzip, bzip2, xz, tar) — aby se dalo říct, co klient
poslal, místo holého „není to zip". Bez toho by odesílatel RARu hádal proč.

### Heslo

Bere se z požadavku, **nikdy se nehádá** a nikam se neloguje.

```python
with pyzipper.AESZipFile(src) as zf:
    if password:
        zf.setpassword(password.encode())
```

`pyzipper`, ne standardní `zipfile`: šifrovaný ZIP nese buď staré ZipCrypto,
nebo AES (7-Zip, WinRAR). Stdlib umí jen to první a na AES spadne na
`NotImplementedError`.

> **`pyzipper.BadZipFile` není podtřída `zipfile.BadZipFile`.** Musí se
> jmenovat obě, jinak poškozený archiv shodí celý požadavek na 500 místo
> toho, aby dostal stav `corrupt`. Tahle chyba tam byla; nevracejte ji.

### Čtyři obrany proti obsahu

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

Symlinky se přeskakují podle horních bitů `external_attr` (`S_IFLNK`).
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

57 testovacích funkcí (60 běhů — část je parametrizovaná pro
ZipCrypto i AES), všechny bez sítě a bez access-manageru.

```
tests/test_extract.py    obrany rozbalovaci vrstvy
tests/test_storage.py    obsahove adresovani, hashe, access.log
tests/test_app.py        HTTP vrstva pres app.test_client()
tests/test_auth.py       preklad verdiktu access-manageru a cache
```

Test je pojmenovaný tím, co tvrdí (`test_zip_slip_nezapise_ven`), ne tím,
kterou funkci volá. Když přidáváte obranu, přidejte test, který ji **poruší
při odstranění** — ne test, který jen projde kódem.

HTTP testy podstrkují `auth._whoami` monkeypatchem, takže nepotřebují běžící
access-manager:

```python
monkeypatch.setattr(auth, "_whoami", lambda key, ip: kdo if key == KLIC else None)
auth._cache.clear()          # jinak si test odnese verdikt po predchozim
```

Dvě věci, které stojí za pozornost při psaní dalších:

- **`auth._cache` se musí čistit** mezi testy, jinak druhý test dostane
  verdikt prvního.
- **Realm se bere z `config.AM_REALM`**, ne napevno — jinak test spadne na
  `wrong_realm`, jakmile se změní výchozí konfigurace. (Přesně to se mi
  stalo.)

Regresní testy na chyby, které tu už byly, jsou pojmenované tak, aby to bylo
vidět — `test_urlencoded_telo_neprijde_prazdne` hlídá vyčerpaný Werkzeug
stream, `test_multipart_vetsi_nez_spool_prah` přetečený tmpfs.

## Kontrola dokumentace

Čísla a výčty v dokumentaci se rozejdou s kódem dřív, než si toho někdo
všimne. Proto:

```bash
python3 tools/check-docs.py
```

Ověří, že v docs nechybí žádný endpoint, chybový kód, stav rozbalení ani
proměnná prostředí, že sedí počty řádků a testů a že nikam nevede mrtvý
odkaz. Vrací nenulový kód, takže se dá pověsit do CI. Pusťte ho po každé
změně, která přidává endpoint, stav nebo parametr.

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
