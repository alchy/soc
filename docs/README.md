# Dokumentace

| dokument | pro koho | co v něm je |
|---|---|---|
| [klient.md](klient.md) | **autor klienta** | jak napsat uploader — co server neodpustí, na čem se dá stavět, checklist před provozem |
| [api.md](api.md) | autor klienta, ladění | drátová reference: cesty, hlavičky, tvary odpovědí, chybové stavy |
| [nasazeni.md](nasazeni.md) | **provozovatel** | celý postup od prázdného stroje: realm, klíč, kontejner, proxy, ověření |
| [install-container.md](install-container.md) | provozovatel | hluboký ponor do kontejneru: rootless podman, síť, zpevnění, potíže |
| [provoz.md](provoz.md) | provozovatel | denní provoz: logy, diagnostika, běžné úkony, sledování |
| [kod.md](kod.md) | **kdo bude kód měnit** | mapa modulů, tok požadavku, místa, kde se dá udělat chyba |
| [design.md](design.md) | kdo bude kód měnit | model hrozeb a proč je to postavené takhle |

## Odkud začít

**Píšu klienta** → [klient.md](klient.md), pak [api.md](api.md) na detaily.

**Nasazuji to** → [nasazeni.md](nasazeni.md) odshora dolů. Nevynechávejte
krok 5 (ověření) — origin ACL se dá nastavit špatně tak, že to vypadá
funkčně.

**Něco nefunguje** → [provoz.md](provoz.md), oddíl Diagnostika.

**Budu to měnit** → [design.md](design.md) na to, proč je to tak, pak
[kod.md](kod.md) na to, kde co je.

## Dvě věci, které jsou v každém z nich

Protože obojí je tiché, projeví se to až škodou a stálo to čas už jednou:

1. **Vault nesmí ležet pod webrootem.** Jinak je každý přijatý malware vzorek
   stažitelný z internetu.
2. **`SOC_TRUSTED_PROXIES` musí odpovídat adrese, pod kterou služba vidí
   proxy.** Jinak jde do access-manageru adresa proxy místo klienta a origin
   ACL přestane rozlišovat kohokoli — bez jediné chybové hlášky.
