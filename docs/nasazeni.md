# Nasazení

*Celý postup od prázdného stroje po funkční příjem vzorku.*

Podmanovské detaily (rootless, pasta, zpevnění) jsou v
[install-container.md](install-container.md); tady je pořadí kroků a to, co
se mezi nimi dá pokazit.

## Co musí být hotové předem

| | |
|---|---|
| **access-manager** | běžící instance, [github.com/alchy/access-manager](https://github.com/alchy/access-manager) |
| **reverzní proxy** | nginx nebo caddy s TLS |
| **doména** | s certifikátem |
| **podman** | 4.3+ (kvůli `--userns=keep-id:uid=…`), ověřeno na 5.8 |

Služba mluví holým HTTP a publikuje port jen na `127.0.0.1`. **Proxy není
volitelná** — bez ní není API dostupné odjinud než z toho stroje.

## 1. Realm a klíč v access-manageru

Realm vzniká **deklarací v konfiguraci**, ne přes API ani konzoli:

```json
// conf.d/realms/soc.example.com.json
{ "name": "soc.example.com", "admins": ["jindrich"] }
```

```bash
systemctl reload access-manager-container
```

Reload je SIGHUP dovnitř kontejneru: přenačte `conf.d`, doplní jen to, co
chybí, a **sokety zůstávají** — ostatní realmy ani přihlášené správce to
neshodí.

Reconcile vyrobí správci párovací token. Platí **14 dní nebo do prvního
úspěšného přihlášení**:

```bash
cat <data>/realm-soc.example.com/admin-<jmeno>/totp.txt
```

> Realmy jsou záměrně neprostupné. Když tentýž člověk spravuje víc realmů,
> má v každém **vlastní** tajemství a v autentikátoru dvě položky. Kopírovat
> `totp.secret` mezi realmy jde, ale znamená to jedno tajemství pro obojí —
> odvolání v jednom pak druhý nechrání.

Pak aplikační klíč. Registruje se knihovnou `Admin` na serveru nebo přes
konzoli (stránka Aplikace):

```python
from access_manager import Admin
admin = Admin.local("<data>", realm="soc.example.com", actor="admin:jindrich")
print(admin.register_component("socupload", detail=False))   # TED, pak uz nikdy
```

Klíč se zobrazí **právě jednou**; na serveru zůstává jen jeho sha256 otisk.
Zapište ho rovnou do souboru s právy 0600, ne na obrazovku.

### Origin ACL — druhý faktor

```python
admin.add_origin("socupload", "203.0.113.0/24")    # rozsah organizace
admin.add_origin("socupload", "127.0.0.1/32")      # lokalni diagnostika
```

Rozsahy i `detail` se mění **bez zásahu do klíče** a platí okamžitě.

> **Prázdné `origins` neznamená „kdokoli", znamená „jen smyčka"** — a služba
> v kontejneru žádný požadavek jako smyčkový nevidí. Komponenta s prázdnými
> `origins` proto dostane `403` na všechno.

## 2. Hostitel

```bash
git clone https://github.com/alchy/soc.git /www/soc/repo
cd /www/soc/repo
sudo deploy/install-container.sh
```

Skript je idempotentní: založí uživatele `soc` (zamčený) a adresáře, deleguje
subuid/subgid, zapne linger a nainstaluje `container-run.sh` plus systemd
unit. Podrobně proč každá z těch věcí, viz
[install-container.md](install-container.md).

## 3. Obraz a start

```bash
sudo -u soc -H XDG_RUNTIME_DIR=/run/user/$(id -u soc) \
     /www/soc/repo/deploy/container-build.sh
sudo systemctl enable --now soc-api-container
```

Obraz stavějte **jako uživatel, pod kterým poběží** — rootless podman drží
úložiště obrazů v jeho domovském adresáři.

Parametry běhu se přebíjejí v `/etc/sysconfig/soc-api-container`; výčet
vypíše `soc-api-container --help`.

## 4. Reverzní proxy

Vzor je v [`deploy/nginx-soc.conf.example`](../deploy/nginx-soc.conf.example).
Tři věci, na kterých záleží:

```nginx
location /api/ {
    client_max_body_size 50m;              # musi sedet se SOC_MAX_UPLOAD
    proxy_pass http://127.0.0.1:8095;
    proxy_set_header X-Real-IP $remote_addr;   # NIKDY od klienta
    proxy_read_timeout 300s;               # velky vzorek po pomale lince
}
```

**`X-Real-IP` přepisujte vždy** adresou peera. Ta hlavička určuje origin ACL
v access-manageru — kdyby si ji směl nastavit klient, obešel by ho.

**Limity musí sedět.** Když se `client_max_body_size` a `SOC_MAX_UPLOAD`
rozejdou, jeden z nich mlčky vyhraje a chybová hláška bude z jiné vrstvy,
než čekáte.

**413 vracejte jako JSON.** Tuhle chybu vrací ještě nginx a aplikace ji nikdy
neuvidí, takže bez `error_page` dostane klient HTML uprostřed jinak JSONového
API:

```nginx
error_page 413 = @too_large;               # na urovni SERVERU, ne v location

location @too_large {
    default_type application/json;
    return 413 '{"error":"too_large","max_bytes":52428800}';
}
```

Uvnitř `location` se u 413 neuplatní — tělo se utne dřív, než se k jeho
`error_page` dojde.

> **Vault nesmí ležet pod webrootem.** Když na téže doméně běží i statický
> web, ověřte to: `curl https://<doména>/vault/` musí vrátit `404`. Jinak je
> každý přijatý vzorek stažitelný z internetu.

## 5. Ověření

Postupujte odspodu — každý krok předpokládá ten předchozí.

```bash
# 1. zije sluzba?
curl -s http://127.0.0.1:8095/api/v1/healthz
# {"status":"ok","vault":"/var/lib/soc/vault","vault_writable":true}

# 2. vidi z kontejneru na access-manager?
podman logs soc-api | tail -1        # "starting" s am_url

# 3. plati klic?
curl -s -H "Authorization: Bearer $KEY" -H "X-Real-IP: 203.0.113.5" \
     http://127.0.0.1:8095/api/v1/samples

# 4. odmita to adresu mimo rozsah?
curl -s -H "Authorization: Bearer $KEY" -H "X-Real-IP: 8.8.8.8" \
     http://127.0.0.1:8095/api/v1/samples
# {"error":"origin_denied",...}

# 5. projde cely retez pres proxy?
curl -X POST https://<domena>/api/v1/samples \
     -H "Authorization: Bearer $KEY" \
     -H "Content-Type: application/octet-stream" \
     -H "X-Filename: test.tgz" --data-binary @test.tgz
```

### Ověření, které se nesmí vynechat

Krok 4 je jediný, který dokáže, že origin ACL **skutečně rozlišuje**. Zkontrolujte
u něj log:

```bash
podman logs soc-api | grep auth_denied | tail -1
```

```json
{"event":"auth_denied","peer":"192.0.2.10","client_ip":"8.8.8.8",
 "trusted_proxy":true,"error":"origin_denied"}
```

`trusted_proxy` musí být `true` a `client_ip` se musí lišit od `peer`. Když
je `false`, jde do access-manageru adresa proxy místo klienta a origin ACL
nerozlišuje nikoho — přitom to zvenku vypadá funkčně.

> **Test, který nic nedokáže:** požadavek ze stejného stroje, kde služba
> běží. `peer` a skutečná adresa klienta pak můžou být tatáž hodnota, takže
> obě čtení dají stejný výsledek. Rozliší to až `X-Real-IP`, které se od
> `peer` liší — proto je v kroku 4 `8.8.8.8`.

## 6. Zpevnění, které stojí za kontrolu

Zpevňuje se ve dvou vrstvách; podrobně v
[install-container.md](install-container.md), tady je kontrolní seznam.

**Hostitel** — kdyby se někdo dostal z kontejneru ven, stojí tam jako `soc`:

```bash
systemctl show soc-api-container -p NoNewPrivileges -p RestrictSUIDSGID
# NoNewPrivileges=yes
# RestrictSUIDSGID=yes
sudo -l -U soc          # User soc is not allowed to run sudo
```

`NoNewPrivileges` nechá suid binárky spustitelné, ale připraví je o účinek —
`sudo` skončí na *„The 'no new privileges' flag is set"*. Platí to pro procesy
spuštěné tímhle unitem; shell získaný přes `sudo -iu soc` potomkem unitu není.

**Kontejner**:

```bash
podman exec soc-api grep CapEff /proc/self/status              # 0000000000000000
podman exec soc-api find / -xdev -perm /6000 -type f           # prazdne
podman exec soc-api ls /www                                     # neexistuje
podman exec soc-api touch /app/x                                # Read-only file system
podman exec soc-api grep /var/lib/soc/vault /proc/self/mounts   # nosuid,nodev,noexec
```

Zapisovatelná místa jsou právě tři: vault, `/var/log/soc` (obojí mount
z hostitele) a `/tmp` na tmpfs — a všechna tři s `nosuid,nodev,noexec`. To je
hlavní důvod, proč služba běží v kontejneru: rozbaluje cizí malware a mount
je tvrdší hranice než `ReadWritePaths` v systemd unitu.

## Aktualizace

```bash
git -C /www/soc/repo pull
sudo -u soc -H XDG_RUNTIME_DIR=/run/user/$(id -u soc) \
     /www/soc/repo/deploy/container-build.sh
sudo systemctl restart soc-api-container
```

Konfigurace jde proměnnými prostředí, takže `reload` nedává smysl — změna
parametru znamená restart. Vault restart nepřežívá jen tak — **přežívá vždy**,
je to mount na hostiteli.

## Zálohy a retence

**Retence není žádná** — vzorky se nemažou samy. To je záměr: smazaný vzorek
nejde vrátit a rozhodnutí, jak dlouho je držet, patří provozovateli.

Zálohuje se `vault/` na hostiteli. Obraz zálohovat netřeba, staví se z gitu.

> Záloha vaultu je záloha **malware vzorků**. Patří tam, kde s tím počítáte —
> ne do sdíleného úložiště, kde na ně narazí něčí antivirus nebo kolega.

## Návrat k nativnímu provozu

`deploy/soc-api.service` pořád platí. Zastavit kontejner, nainstalovat ten
unit a **vrátit hostitelské cesty**: `SOC_VAULT` na `/www/soc/vault`,
`SOC_BIND_HOST` na `127.0.0.1`, `SOC_AM_URL` na `http://127.0.0.1:22000`
a `SOC_TRUSTED_PROXIES` na `127.0.0.1,::1`.
