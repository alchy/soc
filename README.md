# soc-api

**Příjem malware vzorků k analýze.** Analytik z prostředí organizace pošle
archiv, služba ho uloží pod jeho otiskem, pokusí se ho rozbalit a vede o něm
auditní stopu — kdo, odkud, kdy, čím se prokázal a co v archivu bylo.

Autentizaci a autorizaci **nedělá sama**: staví na
[access-manageru](https://github.com/alchy/access-manager) — klient se prokazuje
aplikačním klíčem realmu a rozsahy povolených adres drží access-manager.

Analyzátor vzorků zatím není součástí; API pro něj má připravené místo
(`state` v manifestu, endpoint `/analysis`), aby šel přidat bez změny klientů.

## Model

Zdrojem je **vzorek**, adresovaný svým **sha256**. Adresa je odvozená z obsahu,
takže je příjem přirozeně idempotentní: tentýž vzorek podruhé není chyba ani
duplikát v úložišti — jen další řádek v jeho `access.log`. („Kdo poslal totéž
znovu" je pro SOC informace, ne šum.)

MD5 a SHA1 se počítají také, protože v nich se vzorky mezi týmy běžně
dohledávají. Identitou je ale sha256.

## Rychlý start

Cílený způsob nasazení je **rootless kontejner** — služba rozbaluje cizí
malware a mount je tvrdší hranice než `ReadWritePaths` v systemd unitu:

```bash
sudo deploy/install-container.sh
sudo -u soc -H XDG_RUNTIME_DIR=/run/user/$(id -u soc) deploy/container-build.sh
sudo systemctl enable --now soc-api-container
```

Podrobnosti, včetně dvou míst, kde se síť dá nastavit špatně tak, že to
vypadá funkčně: [docs/install-container.md](docs/install-container.md).

Nativně (vývoj, jednostrojové nasazení):

```bash
pip install -e .
SOC_VAULT=/var/lib/soc/vault python -m soc_api
```

Služba poslouchá na `127.0.0.1:8095`. TLS a limit velikosti těla terminuje
reverzní proxy před ní — vzor je v [`deploy/`](deploy/).

```bash
curl -X POST https://soc.example.com/api/v1/samples \
     -H "Authorization: Bearer $SOC_KEY" \
     -H "Content-Type: application/octet-stream" \
     -H "X-Filename: sample.zip" \
     --data-binary @sample.zip
```

> `Content-Type: application/octet-stream` uveďte. Bez něj posílá curl
> `x-www-form-urlencoded` a tělo se interpretuje jako formulář.

## Endpointy

| metoda a cesta | co dělá |
|---|---|
| `POST /api/v1/samples` | příjem vzorku → `201`, při duplicitě `200` |
| `GET /api/v1/samples?limit=N&include=events` | posledních N, od nejnovějšího |
| `GET /api/v1/samples/{sha256}` | manifest včetně `events` a `files` |
| `GET /api/v1/samples/{sha256}/events` | access.log vzorku |
| `GET /api/v1/samples/{sha256}/files` | rozbalené soubory s hashi |
| `GET /api/v1/samples/{sha256}/analysis` | stav analýzy |
| `GET /api/v1/healthz` | provoz, bez klíče |

Podrobnosti včetně tvarů odpovědí: [docs/api.md](docs/api.md).
Píšete-li klienta, začněte u [docs/klient.md](docs/klient.md).

## Autentizace a origin ACL

Klient posílá aplikační klíč realmu:

```
Authorization: Bearer am_k1_…
```

Klíč se ověřuje u access-manageru (`GET /v1/whoami`, krátká cache). Vedle klíče
platí **origin ACL** — a stojí za to vědět, jak:

Access-manager čte `X-Forwarded-For` od adres, které má v `trusted_proxies`.
soc-api tuto hlavičku nastavuje na **skutečnou adresu klienta**, takže rozsahy
povolené u komponenty rozhodují o tom, odkud smí vzorky chodit. Klíč uniklý
mimo tyto sítě je bezcenný — je to druhý nezávislý faktor, ne kosmetika.

Bez toho přepsání by access-manager měřil adresu serveru, na kterém soc-api
běží, a origin ACL by neznamenal nic.

Hlavičce se přitom věří jen tehdy, když spojení přišlo od vlastní proxy
(`SOC_TRUSTED_PROXIES`); jinak by si ji klient mohl nastavit sám.

> **V kontejneru není proxy vidět na `127.0.0.1`.** Pasta překládá zdrojovou
> adresu na adresu hostitele, takže `SOC_TRUSTED_PROXIES` musí obsahovat
> právě ji — `container-run.sh` ji zjišťuje za běhu. Špatná hodnota nic
> neohlásí, jen origin ACL přestane rozlišovat klienty; jak to ověřit, je
> v [docs/install-container.md](docs/install-container.md).

## Rozbalování

Rozbaluje se **cizí, záměrně škodlivý archiv** — každá položka v něm je
tvrzení útočníka, ne fakt. Proto se nic nebere na slovo:

- cesta mimo cílový adresář (zip-slip) — odmítnuta,
- symlinky, hardlinky, zařízení, fify — přeskočeny,
- tři nezávislé stropy proti dekompresním bombám: celková velikost, poměr
  k originálu a počet položek,
- z výsledku se odebírá `x` bit.

Přeskočené položky se vypíšou v `skipped` — nezmizí potichu.

**Originál zůstává nedotčený vždy.** Když rozbalení nejde, není to chyba
příjmu; vzorek se uloží a dostane stav:

| `extraction.status` | význam |
|---|---|
| `extracted` | rozbaleno |
| `cannot_decompress` | nelze rozbalit — důvod v `info` |
| `not_an_archive` | není zip ani tar; uložen jen originál |
| `corrupt` | archiv je poškozený |

Hesla se **nehádají**. Heslovaný archiv skončí jako `cannot_decompress`
s vysvětlením v `info`.

## Úložiště

```
vault/<sha256[:2]>/<sha256>/
    original/<původní-název>     nikdy se nemění
    extracted/                   rozbalený obsah
    manifest.json                metadata
    access.log                   JSONL, jeden řádek = jedna událost
```

Sharding podle dvou znaků hashe drží počet položek v jednom adresáři rozumný
i po desetitisících vzorků.

> **Vault nesmí ležet pod webrootem.** Kdyby ležel, byl by každý přijatý
> vzorek stažitelný z internetu přes statický web na téže doméně.

## Konfigurace

Vše přes proměnné prostředí, výchozí hodnoty v [`soc_api/config.py`](soc_api/config.py).

| proměnná | výchozí | co dělá |
|---|---|---|
| `SOC_VAULT` | `/www/soc/vault` | úložiště vzorků |
| `SOC_MAX_UPLOAD` | 50 MB | strop na vzorek |
| `SOC_MAX_EXTRACT` | 1 GB | strop na rozbalený obsah |
| `SOC_MAX_RATIO` | 100 | maximální poměr dekomprese |
| `SOC_MAX_FILES` | 10000 | maximální počet položek v archivu |
| `SOC_AM_URL` | `http://127.0.0.1:22000` | access-manager |
| `SOC_AM_REALM` | `soc.autumnpartials.com` | očekávaný realm klíče |
| `SOC_AM_CACHE_S` | 30 | jak dlouho platí verdikt o klíči |
| `SOC_TRUSTED_PROXIES` | `127.0.0.1,::1` | komu se věří `X-Real-IP` |
| `SOC_LOG_DIR` | — (jen stdout) | kam psát `access.log`; v kontejneru `/var/log/soc` |
| `SOC_LOG_MAX_BYTES` | 50 MB | velikost před rotací |
| `SOC_LOG_BACKUPS` | 10 | kolik rotovaných souborů držet |
| `SOC_BIND_HOST` / `SOC_BIND_PORT` | `127.0.0.1` / `8095` | kde poslouchat |

`SOC_MAX_UPLOAD` musí odpovídat `client_max_body_size` na proxy — jinak jeden
z nich mlčky vyhraje.

## Testy

```bash
pip install -e '.[dev]'
pytest
```

Testy běží bez sítě a bez access-manageru; ověřují hlavně obrany
rozbalovací vrstvy (zip-slip, bomby, symlinky, heslované archivy).

## Nasazení

| soubor | k čemu |
|---|---|
| [`deploy/install-container.sh`](deploy/install-container.sh) | připraví hostitele (uživatel, subuid/subgid, linger, unit) |
| [`Dockerfile`](Dockerfile) | definice obrazu |
| [`deploy/container-build.sh`](deploy/container-build.sh) | postaví obraz — [návod](docs/install-container.md#sestavení-obrazu) |
| [`deploy/container-run.sh`](deploy/container-run.sh) | parametry běhu; unit ho jen volá |
| [`deploy/soc-api-container.service`](deploy/soc-api-container.service) | systemd unit (kontejner) |
| [`deploy/soc-api.service`](deploy/soc-api.service) | systemd unit (nativní běh) |
| [`deploy/nginx-soc.conf.example`](deploy/nginx-soc.conf.example) | vzor vhostu |

Poznámky, které stojí za přečtení dřív než po prvním incidentu, jsou
v komentářích těch souborů a v [docs/install-container.md](docs/install-container.md).

### Izolace

Zpevňuje se ve dvou vrstvách — uvnitř kontejneru a na hostiteli, kde by
stál útočník po úniku z něj.

```
# uvnitr kontejneru
CapEff: 0000000000000000      zadne schopnosti
/www                          hostitelsky strom uvnitr neexistuje
/app                          Read-only file system
find / -perm /6000            zadna suid binarka
vault, /var/log/soc, /tmp     jedine zapisy, vsechny nosuid,nodev,noexec

# na hostiteli (systemd unit)
NoNewPrivileges=yes           sudo/su/pkexec ztraceji ucinek
RestrictSUIDSGID=yes          sluzba nevyrobi suid soubor
User=soc                      zamceny ucet mimo sudoers
```

`NoNewPrivileges` chrání před únikem **ze služby**; shell získaný jinak
(`sudo -iu soc`, ssh) potomkem unitu není. Podrobně v
[docs/install-container.md](docs/install-container.md).

## Dokumentace

| dokument | pro koho |
|---|---|
| [docs/klient.md](docs/klient.md) | autor klienta — jak napsat uploader |
| [docs/api.md](docs/api.md) | drátová reference API |
| [docs/nasazeni.md](docs/nasazeni.md) | provozovatel — celý postup nasazení |
| [docs/install-container.md](docs/install-container.md) | provoz v kontejneru do hloubky |
| [docs/provoz.md](docs/provoz.md) | logy, diagnostika, běžné úkony |
| [docs/kod.md](docs/kod.md) | průvodce kódem |
| [docs/design.md](docs/design.md) | model hrozeb a návrhová rozhodnutí |

Rozcestník s tím, odkud začít: [docs/README.md](docs/README.md).

## Licence

Apache 2.0, viz [LICENSE](LICENSE).
