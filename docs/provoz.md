# Provoz

*Kde se co dozvíte, co dělat když, a co při zásazích nerozbít.*

## Kde co leží

| | |
|---|---|
| služba | `systemctl status soc-api-container` |
| log služby | `~soc/logs/service.log`, taky `podman logs soc-api` |
| vault | `~soc/vault/<sha256[:2]>/<sha256>/` |
| access.log vzorku | v adresáři vzorku |
| repozitář | `~soc/repo` — odtud se staví obraz |
| klíč aplikace | u provozovatele, ne na stroji |
| parametry běhu | `/etc/sysconfig/soc-api-container` |

## Log a triáž

Jeden řádek, jeden JSON objekt. **Běžný provoz na `stdout`, potíže na
`stderr`** — odmítnutý požadavek není chyba procesu, služba se právě
zachovala správně.

```bash
podman logs soc-api | tail -20
grep ' stderr F ' ~soc/logs/service.log      # jen to, co chce pozornost
```

Na začátku řádku v souboru je razítko a proud, které píše podman; za `F` je
vlastní záznam služby. Razítko `t` **uvnitř** JSON objektu si píše služba
a je v UTC.

### Události

| `event` | kdy |
|---|---|
| `starting` | při startu, s celou konfigurací |
| `auth_denied` | odmítnutý požadavek, s diagnostikou původu |

Startovní řádek je první, kam se podívat — říká, s čím služba skutečně běží:

```json
{"event":"starting","vault":"/var/lib/soc/vault",
 "am_url":"http://169.254.1.2:22000","am_realm":"soc.example.com",
 "trusted_proxies":["192.0.2.10","169.254.1.2","127.0.0.1","::1"],
 "max_upload":52428800}
```

## Diagnostika

### „Všechno vrací 403 origin_denied"

Nejdřív zjistěte, **jakou adresu služba poslala** do access-manageru:

```bash
podman logs soc-api | grep auth_denied | tail -1
```

```json
{"event":"auth_denied","peer":"192.0.2.10","client_ip":"203.0.113.5",
 "trusted_proxy":true,"error":"origin_denied"}
```

| co vidíte | co to znamená |
|---|---|
| `trusted_proxy: true`, `client_ip` je adresa klienta | správně — klient prostě není v povoleném rozsahu, rozšiřte `origins` |
| `trusted_proxy: false` | `SOC_TRUSTED_PROXIES` neodpovídá adrese, pod kterou služba vidí proxy |
| `client_ip` == `peer` | hlavička nedorazila — proxy ji neposílá, nebo se jí nevěří |

Druhý řádek tabulky je ta tichá porucha: origin ACL přestane rozlišovat
klienty a **nic to neohlásí**. Adresu, kterou má `SOC_TRUSTED_PROXIES`
obsahovat, zjišťuje `container-run.sh` za běhu — když se nezjistila,
podívejte se na startovní řádek logu.

Druhá strana téhož je audit access-manageru:

```bash
tail -3 <data>/realm-<realm>/audit/$(date -u +%F).jsonl
```

```json
{"kind":"origin_denied","component":"socupload","key_id":"k1",
 "origin":"203.0.113.5"}
```

V `origin` musí být **adresa klienta**. Když tam vidíte adresu serveru nebo
kontejneru, hlavička se cestou ztratila.

### „502 auth_backend_error"

Služba nedosáhne na access-manager.

```bash
systemctl status access-manager-container
curl -s http://127.0.0.1:22000/healthz              # z hostitele
podman exec soc-api python -c \
  "import urllib.request;print(urllib.request.urlopen('http://169.254.1.2:22000/healthz').read())"
```

Když funguje první a ne druhé, je problém v mapování hostitelské smyčky
(`--map-host-loopback`), ne v access-manageru.

### „401 unauthorized na platný klíč"

Klíč byl odvolán, nebo patří jinému realmu. Ověřte přímo u autority:

```bash
curl -s -H "Authorization: Bearer $KEY" -H "X-Forwarded-For: <adresa v origins>" \
     http://127.0.0.1:22000/v1/whoami
# {"component":"socupload","key_id":"k1","realm":"soc.example.com"}
```

Bez `X-Forwarded-For` dostanete `403` i s platným klíčem — access-manager
v kontejneru nevidí žádné volání jako smyčkové.

### „Klient dostává HTML místo JSON"

Skoro jistě `413` od nginx, kterou aplikace nikdy neuvidí. Chybí `error_page`
na úrovni serveru — viz [nasazeni.md](nasazeni.md), krok 4.

### „Do vaultu chodí prázdné vzorky"

Klient neposílá `Content-Type: application/octet-stream`. Server pak tělo
vezme jako formulář. Odpověď je `400 empty_body`, nic se neuloží.

### Kontejner nenaběhne

| hláška | příčina |
|---|---|
| `creating systemd unit ... got failed` | chybí `--cgroup-manager=cgroupfs` nebo `Delegate=yes` |
| `PermissionError: ... '/www'` | `SOC_VAULT` je hostitelská cesta místo cesty v kontejneru |
| běží, port nereaguje | `SOC_BIND_HOST` je `127.0.0.1` místo `0.0.0.0` |
| `podman stop` trvá 10 s | chybí `--init` |

## Běžné úkony

### Rozšířit povolený rozsah adres

Bez výměny klíče, platí okamžitě:

```python
from access_manager import Admin
admin = Admin.local("<data>", realm="soc.example.com", actor="admin:jindrich")
admin.add_origin("socupload", "198.51.100.0/24")
admin.remove_origin("socupload", "203.0.113.0/24")
```

Nebo v konzoli access-manageru na stránce Aplikace.

### Vyměnit klíč

```python
admin.revoke_component("socupload")
print(admin.register_component("socupload", detail=False))   # novy, jednou
admin.add_origin("socupload", "203.0.113.0/24")              # origins znovu
```

Odvolání platí okamžitě, ale běžící soc-api si verdikt cachuje — plný účinek
do `SOC_AM_CACHE_S` (30 s). Kdo chce hned, restartuje službu.

### Zvýšit limit velikosti

**Na dvou místech**, jinak jeden mlčky vyhraje:

```
/etc/sysconfig/soc-api-container     SOC_MAX_UPLOAD=104857600
nginx location /api/                 client_max_body_size 100m;
```

Plus text v `error_page` pro 413. Pak `systemctl restart soc-api-container`
a `systemctl reload nginx`.

### Prohlédnout si vzorek

```bash
sudo -u soc cat ~soc/vault/<ab>/<sha256>/manifest.json
sudo -u soc cat ~soc/vault/<ab>/<sha256>/access.log
sudo -u soc ls -la ~soc/vault/<ab>/<sha256>/extracted/
```

> `extracted/` obsahuje **živý malware**. Nespouštějte to, nekopírujte to na
> sdílené úložiště a nepouštějte na to nástroje, které soubory otevírají
> „pro náhled". Soubory nemají `x` bit, ale to je poslední pojistka, ne
> ochrana.

### Smazat vzorek

Retence není žádná, takže mazání je ruční a nevratné:

```bash
sudo -u soc rm -rf ~soc/vault/<ab>/<sha256>/
```

Smaže to i jeho `access.log`, tedy stopu, že vzorek kdy dorazil. Když jde
o audit, zvažte přesun místo smazání.

### Aktualizace

```bash
git -C ~soc/repo pull
sudo -u soc -H XDG_RUNTIME_DIR=/run/user/$(id -u soc) ~soc/repo/deploy/container-build.sh
sudo systemctl restart soc-api-container
```

Vault je mount na hostiteli — restart ani přestavení obrazu se ho nedotkne.

## Sledování

Služba nemá metriky. Co dává smysl hlídat zvenku:

| co | jak |
|---|---|
| žije | `GET /api/v1/healthz` → `200`, `vault_writable: true` |
| kontejner je zdravý | `podman ps` → `(healthy)` |
| místo na disku | vault neroste omezeně a nic ho neuklízí |
| tiché ztráty | `grep '"trusted_proxy": false' ~soc/logs/service.log` |

Poslední řádek je levná pojistka proti té chybě, která se jinak neprojeví.

## Po rebootu

Nic se nedělá — `soc-api-container` je `enabled` a uživatel `soc` má linger,
takže rootless podman naběhne bez přihlášení. Ověření:

```bash
systemctl is-enabled soc-api-container    # enabled
loginctl show-user soc | grep Linger      # Linger=yes
curl -s http://127.0.0.1:8095/api/v1/healthz
```

Kdyby kontejner po bootu nenaběhl a v journalu byla chyba cgroup nebo sběrnice,
chybí linger — viz [install-container.md](install-container.md).
