# Provoz v kontejneru

*Jak postavit obraz, spustit službu jako neprivilegovaný kontejner a nechat
ji startovat se systémem.*

Kontejner tu **není kvůli přenositelnosti**. Služba rozbaluje cizí, záměrně
škodlivý archiv; mount je tvrdší hranice než `ReadWritePaths` v systemd unitu.
Uvnitř nemá proces žádné schopnosti (`CapEff: 0`), kořen je jen pro čtení
a jediné, kam smí zapsat, je namontovaný vault.

## Co je uvnitř a co venku

| | kde | na hostiteli | v kontejneru |
|---|---|---|---|
| kód a závislosti | **v obrazu** | — | `/app` |
| vault se vzorky | **mimo** | `~/vault` | `/var/lib/soc/vault` |
| konfigurace | proměnné prostředí | `container-run.sh` | — |
| access log | **mimo**, mount | `~/logs/access.log` | `/var/log/soc/access.log` |
| provozní log | **mimo** | `~/logs/service.log` | — (píše ho podman ze stdout) |
| TLS | **mimo** | reverzní proxy | — |

> **`/var/lib/soc/vault` na hostiteli neexistuje.** Je to přípojný bod uvnitř
> kontejneru. Kdo do `SOC_VAULT` propašuje hostitelskou cestu, dostane
> `PermissionError: [Errno 13] Permission denied: '/www'`.

## Instalace

```bash
sudo deploy/install-container.sh
```

Skript je idempotentní a udělá čtyři věci: založí uživatele a adresáře,
**deleguje subuid/subgid**, **zapne linger** a nainstaluje `container-run.sh`
jako `/usr/local/bin/soc-api-container` plus systemd unit.

Pak obraz a start:

```bash
sudo -u soc -H XDG_RUNTIME_DIR=/run/user/$(id -u soc) \
     deploy/container-build.sh
sudo systemctl enable --now soc-api-container
```

Obraz stavějte **jako uživatel, pod kterým poběží** — rootless podman drží
úložiště obrazů v jeho domovském adresáři, takže obraz postavený rootem by
`podman run` toho uživatele vůbec nenašel.

## Síť: dvě věci, které se snadno rozbijí potichu

Služba je zároveň **server** (nginx k ní chodí) i **klient** (chodí do
access-manageru). Oba směry procházejí překladem adres a oba se dají nastavit
špatně tak, že to vypadá funkčně.

### Ven: jak se dostat na access-manager

Access-manager publikuje porty jen na `127.0.0.1` hostitele — a to je adresa,
kam kontejner nedosáhne; jeho `127.0.0.1` je jeho vlastní smyčka. Řeší to
pasta:

```
--network pasta:--map-host-loopback,169.254.1.2
```

Uvnitř kontejneru pak `169.254.1.2` znamená smyčku hostitele, takže
`SOC_AM_URL=http://169.254.1.2:22000` míří na access-manager. Link-local
adresa je zvolená záměrně: nekoliduje s ničím, co by služba mohla chtít
skutečně oslovit, a na rozdíl od výchozího `--map-gw` nezávisí na tom, jak
vypadá síť hostitele.

### Dovnitř: komu věřit hlavičku `X-Real-IP`

Tohle je nejzrádnější místo celého nasazení.

Nativní služba viděla nginx přicházet z `127.0.0.1`. **Kontejner ho
z `127.0.0.1` nevidí** — pasta překládá zdrojovou adresu spojení
z hostitelské smyčky na adresu hostitele na jeho výchozím rozhraní.

`container-run.sh` ji proto zjišťuje za běhu (`ip route get`) a přidává do
`SOC_TRUSTED_PROXIES`. Napevno zapsaná by se při změně IP stroje tiše
rozešla se skutečností.

Důsledek špatné hodnoty: služba přestane věřit hlavičce a do access-manageru
půjde jako origin **adresa proxy místo adresy klienta**. Origin ACL pak
nerozliší nikoho — a nic to neohlásí.

Ověření po nasazení. Pošlete požadavek přes proxy a přečtěte si log:

```bash
podman logs soc-api | grep auth_denied | tail -1
```

```json
{ "event": "auth_denied", "peer": "192.0.2.10",
  "client_ip": "2001:db8::55", "trusted_proxy": true,
  "error": "origin_denied" }
```

`trusted_proxy` musí být `true` a `client_ip` se musí lišit od `peer`. Když
je `trusted_proxy` false, je `SOC_TRUSTED_PROXIES` špatně.

> Pozor na test, který nic nedokáže: když posíláte požadavek ze stejného
> stroje, na kterém služba běží, může se `peer` a skutečná adresa klienta
> shodovat — a obě čtení pak dají tentýž výsledek. Rozliší to až požadavek
> s `X-Real-IP`, které se od `peer` liší.

## Zpevnění

`container-run.sh` spouští kontejner takto:

| přepínač | proč |
|---|---|
| `--cap-drop ALL` | služba nepotřebuje žádnou schopnost |
| `--security-opt no-new-privileges` | žádné zvýšení oprávnění zevnitř |
| `--read-only` | kořen jen pro čtení; kód nejde přepsat |
| `--tmpfs /tmp` | další zápis, `noexec,nosuid`, mizí s kontejnerem |
| `--userns keep-id:uid=1000,gid=1000` | soubory ve vaultu zůstanou na hostiteli vlastněné `soc` |
| `--init` | bez něj Python jako PID 1 zahazuje signály a `stop` trvá 10 s |

Ověření:

```bash
podman exec soc-api grep CapEff /proc/self/status   # 0000000000000000
podman exec soc-api ls /www                          # neexistuje
podman exec soc-api touch /app/x                     # Read-only file system
```

## Události

| příkaz | co se stane |
|---|---|
| `systemctl restart soc-api-container` | kontejner se zastaví a spustí znovu |
| `systemctl stop …` | SIGTERM dovnitř, po 15 s SIGKILL |

Konfigurace jde proměnnými prostředí, takže **`reload` nedává smysl** —
změna parametru znamená restart. Přebíjí se v `/etc/sysconfig/soc-api-container`;
úplný výčet vypíše `soc-api-container --help`.

## Aktualizace

```bash
git -C /www/soc/repo pull
sudo -u soc -H XDG_RUNTIME_DIR=/run/user/$(id -u soc) \
     /www/soc/repo/deploy/container-build.sh
sudo systemctl restart soc-api-container
```

## Rootless: co k tomu potřebuje

Čtyři věci, bez kterých to nejede a z hlášek to není poznat — instalátor je
nastaví, tenhle oddíl je pro ladění na jiném stroji:

**subuid/subgid.** Uvnitř obrazu existuje root (0), `soc` (1000) i `nobody`
(65534), venku je jen jedno UID. Jádro proto uživateli deleguje blok
(`300000–365535`). Kdyby proces z kontejneru utekl, je venku uid `300000+`,
které nikomu nepatří.

**Linger.** Rootless podman potřebuje `/run/user/<uid>` a uživatelský systemd.
Bez lingeru vznikají až přihlášením — a služba startující při bootu se nikam
nepřihlašuje.

**`--cgroup-manager=cgroupfs`.** Systémový unit běží v system slice, takže
uživatelský systemd mu cgroup scope vyrobit nemůže. Start skončí na
`creating systemd unit ... got failed`. Proto je v unitu `Delegate=yes`.

**`DBUS_SESSION_BUS_ADDRESS`.** Ze systémového unitu není uživatelská
sběrnice vidět; unit ji ukazuje explicitně na `/run/user/<uid>/bus`.

## Řešení potíží

| hláška / projev | příčina |
|---|---|
| `crun: error creating systemd unit ... got failed` | chybí `--cgroup-manager=cgroupfs` nebo `Delegate=yes` |
| `PermissionError: ... '/www'` | `SOC_VAULT` je hostitelská cesta místo cesty v kontejneru |
| kontejner běží, port nereaguje | `SOC_BIND_HOST` je `127.0.0.1` místo `0.0.0.0` |
| origin ACL nerozlišuje klienty | `SOC_TRUSTED_PROXIES` neodpovídá adrese, pod kterou kontejner vidí proxy |
| `502 auth_backend_error` | z kontejneru není vidět access-manager — zkontrolujte `--map-host-loopback` |
| `podman stop` trvá 10 s | chybí `--init` |
| `HEALTHCHECK is not supported for OCI image format` | build bez `--format docker` |

## Nativní provoz

`deploy/soc-api.service` v repozitáři pořád platí. Vrátit se znamená zastavit
kontejner, nainstalovat ten unit a **vrátit hostitelské cesty** — `SOC_VAULT`
na `/www/soc/vault`, `SOC_BIND_HOST` na `127.0.0.1`, `SOC_AM_URL` na
`http://127.0.0.1:22000` a `SOC_TRUSTED_PROXIES` na `127.0.0.1,::1`.
