# CONTAINER-RULEZ — konformní pravidla pro kontejnerové služby

**Zadání, ne návod.** Tohle je normativní sada pravidel pro každou službu běžící na
tomto stroji v **rootless podman** kontejneru. Agent (nebo člověk) podle nich službu
**ověří** a co nesplňuje, **donastaví**; nová služba se podle nich **připraví**.

Konvence:
- **MUSÍ** = tvrdý požadavek; nesplnění = nekonformní, oprav.
- **MĚLA BY** = doporučení; odchylka je přípustná, když je v komentáři u souboru
  napsaná a zdůvodněná.
- `<s>` = jméno služby, `<user>`/`<uid>` = její systémový účet, `<port>` = její port.
- **Ověření** u pravidla říká, jak konformitu strojově zkontrolovat.
- Pravidla jsou app-agnostická. Kde je uvedeno konkrétní jméno, je to jen příklad.

Každé pravidlo má ID (`IMG-1`, `PXY-3`, …). Report konformity se na ně odkazuje
(`PXY-3: FAIL`).

---

## A. Obraz (`IMG`)

- **IMG-1** — Základ MUSÍ být `python:3.12-slim` (nebo novější schválený base).
  _Ověření:_ `FROM` v Dockerfile.
- **IMG-2** — V obraze NESMÍ být konfigurace, data ani tajemství. Vše se montuje /
  předává za běhu. _Ověření:_ `podman history <img>` + grep Dockerfile na `COPY`
  citlivých cest; obraz musí jít zveřejnit.
- **IMG-3** — Uživatel v obraze MUSÍ mít `uid 1000` (kvůli
  `--userns keep-id:uid=1000,gid=1000`). _Ověření:_ `useradd --uid 1000` v Dockerfile;
  `podman run --rm <img> id -u` = `1000`.
- **IMG-4** — Dockerfile MUSÍ strhnout suid/sgid bity:
  `RUN find / -xdev -perm /6000 -type f -exec chmod -s {} + 2>/dev/null || true`.
  _Ověření:_ `podman run --rm <img> find / -xdev -perm /6000 -type f` nevypíše nic.
- **IMG-5** — Obraz MUSÍ mít `HEALTHCHECK` volající `/healthz` (nebo ekvivalent).
  _Ověření:_ `podman inspect <img> --format '{{.Config.Healthcheck}}'` není prázdné.
- **IMG-6** — Entrypoint MUSÍ naslouchat na `0.0.0.0` uvnitr kontejneru (jinak
  publikovaný port nevede nikam). _Ověření:_ bind adresa v entrypointu / configu.

## B. Build (`BLD`)

- **BLD-1** — Build MUSÍ běžet **jako uživatel služby** (rootless úložiště je v jeho
  `HOME`). Kanonicky: `sudo -u <user> -H XDG_RUNTIME_DIR=/run/user/<uid> deploy/container-build-<s>.sh`.
  _Ověření:_ `sudo -u <user> ... podman images` obraz vidí.
  _Proč:_ obraz postavený jiným účtem `podman run` uživatele služby nenajde → „image not known".
- **BLD-2** — Build MUSÍ použít `podman build --format docker`.
  _Ověření:_ řetězec ve build skriptu.
  _Proč:_ v nativním OCI formátu podman zahodí `HEALTHCHECK` a `podman ps` neukáže `(healthy)`.
- **BLD-3** — Build MUSÍ jít z build skriptu `deploy/container-build-<s>.sh`, ne ad hoc.
  _Ověření:_ existence skriptu.

## C. Běh kontejneru (`RUN`) — vše v run wrapperu

- **RUN-1** — Runtime parametry MUSÍ být **výhradně** v run wrapperu
  `/usr/local/bin/<s>-container`; systemd unit ho jen volá s `--foreground`.
  _Ověření:_ unit `ExecStart` = `/usr/local/bin/<s>-container --foreground`; žádné
  `podman run` flagy přímo v unitu.
- **RUN-2** — Každý parametr MUSÍ mít pořadí přebíjení **default → env → `--flag`** a
  wrapper MUSÍ mít `--help`. _Ověření:_ `<s>-container --help`.
- **RUN-3** — Wrapper MUSÍ být idempotentní: na začátku `podman rm -f <s>` (úklid po
  pádu stroje). _Ověření:_ řetězec ve wrapperu.
- **RUN-4** — Wrapper MUSÍ fail-fast na chybějící vstupy (mounty, tajemství) —
  nespouštět rozbitý kontejner. _Ověření:_ `[ -d ... ] || exit 1` apod.
- **RUN-5** — Publikace portu MUSÍ být jen na `127.0.0.1` (`--publish 127.0.0.1:<port>:<port>`).
  _Ověření:_ `podman port <s>` / `ss -ltnp` ukazuje jen `127.0.0.1`.
- **RUN-6** — MUSÍ být `--userns keep-id:uid=1000,gid=1000`, `--init`, `--rm`,
  `--stop-timeout 15`. _Ověření:_ řetězce ve wrapperu / `podman inspect`.
- **RUN-7** (hardening, tvrdé) — MUSÍ být `--cap-drop ALL` a
  `--security-opt no-new-privileges`. _Ověření:_
  `podman inspect <s>` → `CapDrop` obsahuje `ALL`, `no-new-privileges` v `SecurityOpt`.
- **RUN-8** (hardening) — Kořen MUSÍ být `--read-only` + `--tmpfs /tmp:rw,noexec,nosuid,size=<N>m`;
  zapisovatelný smí být jen konkrétní datový mount. Když to služba neunese, je to
  odůvodněná výjimka v komentáři wrapperu. _Ověření:_ `podman inspect <s>` →
  `ReadonlyRootfs: true`; `touch` v kořeni uvnitř selže.
- **RUN-9** — Datové mounty MUSÍ mít `nosuid,nodev,noexec` a `:ro` všude, kde služba
  jen čte. _Ověření:_ `--volume` řetězce; `podman inspect` mount options.

## D. Síť (`NET`)

- **NET-1** — Vybrat MUSÍ podle potřeby přesně jeden vzor a v komentáři wrapperu
  napsat který a proč:
  - **pasta** (`pasta:--map-host-loopback,<link-local>`) — když kontejner potřebuje
    dosáhnout na službu na smyčce hostitele (typicky AM na `127.0.0.1:22000`).
  - **bridge + pevná IP** (`--network <jméno> --ip <adresa>`) — když služba sama
    potřebuje stabilní zdrojovou adresu (kvůli `trusted_proxies`). Síť zakládat
    idempotentně (`network exists || network create`).
  _Ověření:_ `--network` řetězec + komentář.
- **NET-2** (landmina za pasta) — Adresu, pod kterou kontejner vidí smyčku/klienta
  přes pasta, MUSÍ wrapper **zjistit za běhu** (`ip route get 1.1.1.1`), NE napevno.
  _Ověření:_ `ip route get` ve wrapperu; hodnota se propíše do `trusted_proxies` /
  `X-Forwarded-For` origin ACL.
  _Proč:_ napevno zapsaná IP se po změně sítě tiše rozejde a origin ACL / trusted
  proxy přestane rozlišovat klienta — bez chybové hlášky.

## E. Propagace z nginx (`PXY`)

Kontrakt mezi hostitelským nginx (TLS) a kontejnerem (holé HTTP na 127.0.0.1).

- **PXY-1** — TLS terminuje **jen nginx**; kontejner TLS neterminuje. _Ověření:_ ve
  vhostu je `ssl_certificate`; proxy cíl je `http://127.0.0.1:<port>`.
- **PXY-2** — nginx MUSÍ posílat `X-Forwarded-Proto $scheme` (kvůli Secure cookie a
  redirectům). _Ověření:_ `proxy_set_header X-Forwarded-Proto $scheme`.
- **PXY-3** (bezpečnostní invariant) — Hlavička nesoucí IP klienta MUSÍ být přepsána
  `$remote_addr` (nikdy neprochází od klienta), protože řídí origin ACL /
  `trusted_proxies`. Jméno hlavičky (`X-Real-IP` **nebo** `X-Forwarded-For`) MUSÍ
  odpovídat tomu, co čte aplikace; hop MUSÍ být právě jeden. _Ověření:_ ve vhostu
  `X-Real-IP $remote_addr` / `X-Forwarded-For $remote_addr` (ne `$http_x_...`); v app
  configu odpovídající `trusted_proxies` / ProxyFix `x_for=1`.
  _Proč:_ kdyby si hlavičku směl nastavit klient, obešel by origin ACL.
- **PXY-4** — Aplikace na sub-cestě (`/<s>/…`) MUSÍ dostat `X-Forwarded-Prefix /<s>`
  a číst ho (ProxyFix `x_prefix`); před location bez lomítka MUSÍ být `= /<s>` →
  `return 308 /<s>/`. _Ověření:_ `proxy_set_header X-Forwarded-Prefix`; 308 redirect;
  `url_for` generuje `/<s>/…`. (Služba na kořeni vhostu prefix nepotřebuje.)
- **PXY-5** — Bezpečnostní hlavičky (`X-Content-Type-Options`, `X-Frame-Options`
  nebo CSP `frame-ancestors`, `Strict-Transport-Security`, případně `Content-Security-Policy`)
  MUSÍ být na úrovni **server bloku** s `always`. _Ověření:_ `add_header ... always`
  v server bloku; response je nese.
- **PXY-6** (landmina) — Uvnitř `location` proxy služby NESMÍ být žádný `add_header`,
  pokud se všech server-level hlaviček ručně nezopakuje. _Ověření:_ `location` bloku
  chybí `add_header`, nebo je má kompletní.
  _Proč:_ nginx: první `add_header` v location zruší dědičnost **všech** server-level
  `add_header` → tiché zmizení bezpečnostních hlaviček.
- **PXY-7** — `client_max_body_size` v location MUSÍ odpovídat maximu, které app
  přijímá (jinak jeden z limitů tiše vyhraje); u velkých přenosů zvednout
  `proxy_read_timeout`/`proxy_send_timeout`. _Ověření:_ hodnoty vs. app config;
  API vracející JSON MĚLA BY mít server-level `error_page 413` v JSONu.
- **PXY-8** — Autentizační endpointy MĚLY BY mít nginx `limit_req` navíc nad
  aplikační throttle. _Ověření:_ `limit_req_zone` + `limit_req` u auth location.

## F. Logování (`LOG`)

- **LOG-1** — stdout/stderr kontejneru MUSÍ jít přes `--log-driver k8s-file
  --log-opt path=$HOME/logs/<s>.log --log-opt max-size=<N>m` (`N` ≥ 10), soubor v
  `HOME` uživatele služby (přežije `podman rm`). _Ověření:_
  `podman inspect <s> --format '{{.HostConfig.LogConfig}}'`; soubor existuje a roste.
  Jednotně u všech služeb; přechod na `journald` je celohostitelské rozhodnutí, ne
  per-služba.
- **LOG-2** — Aplikační log psaný mimo stdout (do mountu) MUSÍ mít vlastní rotaci
  (logrotate nebo v aplikaci). _Ověření:_ existence logrotate pravidla / rotace v kódu;
  soubor neroste bez stropu.

## G. Start / systemd unit (`SVC`)

- **SVC-1** — Unit soubor MUSÍ mít mód `0644` a NESMÍ být spustitelný.
  _Ověření:_ `stat -c %a /etc/systemd/system/<s>-container.service` = `644`.
- **SVC-2** — `[Unit]` MUSÍ mít `Wants`+`After network-online.target`,
  `Requires`+`After user@<uid>.service` (linger), a `Wants`+`After` (ne `Requires`)
  závislých služeb. _Ověření:_ řádky v unitu.
  _Proč:_ `user@<uid>` drží `/run/user/<uid>` a sběrnici; závislá služba smí naběhnout
  degradovaně, proto `Wants`.
- **SVC-3** — `[Service]` MUSÍ mít `User`/`Group` účtu služby a čtyři `Environment=`:
  `HOME`, `XDG_RUNTIME_DIR=/run/user/<uid>`, `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus`,
  `PATH=/usr/local/bin:/usr/bin:/bin`. _Ověření:_ řádky v unitu.
  _Proč:_ bez `DBUS_SESSION_BUS_ADDRESS` start skončí na `creating systemd unit ... got failed`.
- **SVC-4** — Unit NESMÍ mít `NoNewPrivileges=yes`. _Ověření:_ grep unitu — nesmí být.
  _Proč:_ rootless podman zakládá user namespace přes `newuidmap` (`cap_setuid=ep`),
  který `NoNewPrivileges` ruší → `newuidmap: write to uid_map failed: Operation not
  permitted` po rebootu (při ručním startu falešně projde). Ochrana je uvnitř
  kontejneru (RUN-7/8) + `RestrictSUIDSGID` (SVC-5).
- **SVC-5** — Unit MUSÍ mít `RestrictSUIDSGID=yes` a `Delegate=yes`. _Ověření:_ řádky
  v unitu. _Proč (`Delegate`):_ systémový unit v system slice si jinak nevytvoří cgroup
  scope → viz i RUN pravidlo o `--cgroup-manager cgroupfs`.
- **SVC-6** — Wrapper i podman MUSÍ běžet s `--cgroup-manager cgroupfs`. _Ověření:_
  řetězec ve wrapperu. _Proč:_ viz SVC-5.
- **SVC-7** — Unit MUSÍ mít `Restart=on-failure`, `RestartSec=5`, `TimeoutStopSec=30`,
  `ExecStopPost=-/usr/bin/podman rm -f <s>`. _Ověření:_ řádky v unitu.

## H. Konfigurace a tajemství (`CFG`)

- **CFG-1** — Nesecretní parametry se předávají hodnotou (`--env "FOO=$FOO"`).
  Tajemství NESMÍ být na příkazové řádce, v obraze ani v gitu. _Ověření:_
  `podman inspect <s>` a `ps` neukážou tajemství; git grep na placeholdery jen v `*.example`.
- **CFG-2** — Tajemství se předává právě jedním z: (a) **prostředím jménem**
  `--env "FOO"` (bez `=`) ze souboru `EnvironmentFile` `0600`; nebo (b) **mountovaným
  datovým adresářem** `0600`. _Ověření:_ jeden ze vzorů; žádné `--env FOO=<realná hodnota>`.
- **CFG-3** — `EnvironmentFile` nesoucí tajemství/povinnou konfiguraci MUSÍ být v unitu
  **bez `-`** (povinný), soubor `0600` a vlastněný účtem služby. Jen ladítka bez
  tajemství → **s `-`** (volitelný), `0644 root:root`, a služba MUSÍ běžet i bez něj na
  defaultech wrapperu. _Ověření:_ `EnvironmentFile` řádek + `stat`/`ls -l` souboru.
- **CFG-4** — Wrapper i entrypoint MUSÍ na chybějící tajemství fail-fast s jasným
  jménem proměnné. _Ověření:_ kontrola v obou skriptech.

## I. Příprava hostitele / deploy (`HST`)

- **HST-1** — Každá služba MUSÍ mít idempotentní `deploy/install-container.sh`
  (spouštěný root), který: založí účet (nepřihlašovací — `nologin`, MĚLA BY; jinak
  aspoň `passwd -l`; nikdy sudoers), založí adresáře, deleguje subuid/subgid, zapne
  linger a nainstaluje wrapper + unit. _Ověření:_ existence a běh skriptu.
- **HST-2** — Účet služby MUSÍ mít **nepřekrývající se** blok subuid/subgid oproti
  ostatním účtům. _Ověření:_ `/etc/subuid`, `/etc/subgid` — bez překryvu rozsahů.
- **HST-3** — Linger MUSÍ být zapnutý (`loginctl enable-linger <user>`). _Ověření:_
  `loginctl show-user <user> --property=Linger` = `yes`.
- **HST-4** — Uživatel se sdílí **jen když se sdílejí data**; jinak nový dedikovaný
  účet. _Ověření:_ posouzení — sdílený `HOME`/účet odpovídá sdílenému mountu.
- **HST-5** — Před službou MUSÍ stát reverzní proxy s TLS podle sekce E; po instalaci
  `nginx -t` projde a služba je `enable --now`. _Ověření:_ `nginx -t`;
  `systemctl is-enabled/is-active <s>-container`; `podman ps` = `(healthy)`.

## J. SELinux (`SEL`)

- **SEL-1** — Mount čtený více kontejnery MUSÍ mít **sdílený** label `:z` (malé).
  Mount jednoho kontejneru MUSÍ mít **privátní** `:Z` (velké). _Ověření:_ `--volume`
  options; při sdílení nesmí být `:Z`. _Proč:_ `:Z` přelabeluje na kategorii jednoho
  kontejneru → druhý dostane „permission denied" i s `:ro`.

---

## Příloha — kanonické skelety

Skelety, ze kterých se odvozuje nová služba. Jsou konformní se všemi pravidly výše;
`<s>`, `<S>`, `<user>`, `<uid>`, `<port>` nahraď.

### Run wrapper (`/usr/local/bin/<s>-container`)

```sh
#!/bin/sh
set -eu
IMAGE="${<S>_IMAGE:-localhost/<s>:latest}"
NAME="${<S>_NAME:-<s>}"
DOMOV="${HOME:-/www/<user>}"
# ... další parametry: default → env → --flag ...
CGROUP_MANAGER="${<S>_CGROUP_MANAGER:-cgroupfs}"      # SVC-6
FOREGROUND=0
# napoveda() { ... --help ... }                        # RUN-2
# ... getopts; --foreground) FOREGROUND=1 ...
[ -d "$DATA" ] || { echo "chybi: $DATA" >&2; exit 1; } # RUN-4
[ -n "${<S>_SECRET:-}" ] || { echo "chybi <S>_SECRET" >&2; exit 1; }  # CFG-4
podman --cgroup-manager "$CGROUP_MANAGER" rm -f "$NAME" >/dev/null 2>&1 || true  # RUN-3
set -- \
    --rm --init --name "$NAME" \
    <SÍŤ: pasta | bridge>                    `# NET-1/2` \
    --publish "127.0.0.1:$PORT:<port>"       `# RUN-5` \
    --userns "keep-id:uid=1000,gid=1000"     `# RUN-6` \
    --volume "$DATA:/...:<ro,z|Z>,nosuid,nodev,noexec"  `# RUN-9 / SEL-1` \
    --env "FOO=$FOO"  --env "SECRET"         `# CFG-1/2` \
    --log-driver k8s-file \
    --log-opt "path=$DOMOV/logs/<s>.log" --log-opt max-size=10m  `# LOG-1` \
    --stop-timeout 15
set -- "$@" \
    --cap-drop ALL --security-opt no-new-privileges   `# RUN-7` \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=32m `# RUN-8`
[ "$FOREGROUND" -eq 1 ] || set -- "$@" --detach
exec podman --cgroup-manager "$CGROUP_MANAGER" run "$@" "$IMAGE"
```

### Systemd unit (`/etc/systemd/system/<s>-container.service`, mód 0644)

```ini
[Unit]
Description=<s> v kontejneru (podman, rootless; :<port>)
Wants=network-online.target
After=network-online.target
Wants=<závislá>.service
After=<závislá>.service
Requires=user@<uid>.service
After=user@<uid>.service

[Service]
Type=simple
User=<user>
Group=<user>
Environment=HOME=/www/<user>
Environment=XDG_RUNTIME_DIR=/run/user/<uid>
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus
Environment=PATH=/usr/local/bin:/usr/bin:/bin
EnvironmentFile=-/etc/sysconfig/<s>-container      # bez `-` když nese tajemství (CFG-3)
ExecStart=/usr/local/bin/<s>-container --foreground
ExecStopPost=-/usr/bin/podman rm -f <s>
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
RestrictSUIDSGID=yes
Delegate=yes
# ŽÁDNÝ NoNewPrivileges (SVC-4)

[Install]
WantedBy=multi-user.target
```

### nginx location (sekce E)

```nginx
location = /<s>  { return 308 /<s>/; }               # PXY-4
location /<s>/ {
    # PXY-6: žádný add_header zde (zrušil by dědičnost bezpečnostních hlaviček)
    proxy_pass http://127.0.0.1:<port>/;
    proxy_http_version 1.1;
    proxy_set_header Host               $host;
    proxy_set_header X-Forwarded-Prefix /<s>;         # PXY-4
    proxy_set_header X-Forwarded-For    $remote_addr; # PXY-3 (nebo X-Real-IP)
    proxy_set_header X-Forwarded-Proto  $scheme;      # PXY-2
    client_max_body_size <max>;                       # PXY-7
}
# server-level, always: X-Content-Type-Options, X-Frame-Options/CSP, HSTS  (PXY-5)
```
