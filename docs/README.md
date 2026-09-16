# Dokumentace

Tento repozitář obsahuje **dvě samostatné komponenty** (monorepo). Běží jako
oddělené procesy/kontejnery a sdílejí **jen** obsah vaultu — jinak spolu nemluví.

| | **soc-api** (příjem) | **soc-portal** (portál) |
|---|---|---|
| Úkol | přijímá vzorky od podnikové brány | zobrazuje analytikům hotové vzorky |
| Vault | **zápis** (RW mount) | **jen čtení** (RO mount) |
| Uživatelé | stroje (brána, komponentní klíč) | lidé (SOC analytici, TOTP login) |
| nginx routa | `/api` | `/portal` |
| Port (smyčka) | `127.0.0.1:8095` | `127.0.0.1:8096` |
| Kód | [`soc_api/`](../soc_api) | [`soc_portal/`](../soc_portal) |
| Dokumentace | níže (soc-api) | [`docs/portal/`](portal/) |

Kontrakt mezi nimi = formát vaultu (`manifest.json`, `extracted/`). soc-api ho
vlastní a zapisuje **atomicky** (temp + rename); soc-portal ho čte a na atomicitu
spoléhá. Tento invariant musí ctít i budoucí orchestrátor analýzy.

---

## soc-api — příjem vzorků

| dokument | pro koho | co v něm je |
|---|---|---|
| [klient.md](klient.md) | **autor klienta** | jak napsat uploader — co server neodpustí, na čem se dá stavět, checklist před provozem |
| [api.md](api.md) | autor klienta, ladění | drátová reference: cesty, hlavičky, tvary odpovědí, chybové stavy |
| [nasazeni.md](nasazeni.md) | **provozovatel** | celý postup od prázdného stroje: realm, klíč, kontejner, proxy, ověření |
| [install-container.md](install-container.md) | provozovatel | hluboký ponor do kontejneru: rootless podman, síť, zpevnění, potíže |
| [provoz.md](provoz.md) | provozovatel | denní provoz: logy, diagnostika, běžné úkony, sledování |
| [kod.md](kod.md) | **kdo bude kód měnit** | mapa modulů, tok požadavku, místa, kde se dá udělat chyba |
| [design.md](design.md) | kdo bude kód měnit | model hrozeb a proč je to postavené takhle |

### Odkud začít (soc-api)

**Píšu klienta** → [klient.md](klient.md), pak [api.md](api.md) na detaily.

**Nasazuji to** → [nasazeni.md](nasazeni.md) odshora dolů. Nevynechávejte
krok 5 (ověření) — origin ACL se dá nastavit špatně tak, že to vypadá funkčně.

**Něco nefunguje** → [provoz.md](provoz.md), oddíl Diagnostika.

**Budu to měnit** → [design.md](design.md) na to, proč je to tak, pak
[kod.md](kod.md) na to, kde co je.

---

## soc-portal — portál SOC týmu

| dokument | pro koho | co v něm je |
|---|---|---|
| [portal/implementation.md](portal/implementation.md) | **kdo bude portál měnit / nasazovat** | vrstvy, datový tok, ADR (proč přímé RO čtení vaultu, Flask, vlastní session, autentizace ≠ autorizace, sandbox nepřátelského HTML), Mermaid diagramy, tabulka konfigurace, provoz |

Nasazení portálu: [`../deploy/nginx-portal.conf.example`](../deploy/nginx-portal.conf.example)
(routa `/portal`), [`../deploy/container-run-portal.sh`](../deploy/container-run-portal.sh)
(rootless podman, RO mount).

---

## Dvě věci společné oběma komponentám

Protože obojí je tiché, projeví se to až škodou a stálo to čas už jednou:

1. **Vault nesmí ležet pod webrootem.** Jinak je každý přijatý malware vzorek
   stažitelný z internetu.
2. **Skutečná adresa klienta z proxy** (`SOC_TRUSTED_PROXIES` u soc-api /
   `X-Forwarded-For` hop u portálu) musí odpovídat realitě. Jinak jde do
   access-manageru adresa proxy místo klienta a origin ACL / audit přestanou
   rozlišovat kohokoli — bez jediné chybové hlášky.
