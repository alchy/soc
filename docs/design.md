# Návrh a jeho důvody

*Proč je to postavené takhle. Rozhodnutí, která nejsou z kódu zřejmá, a to,
proti čemu se služba brání — i to, proti čemu ne.*

## Co to má dělat

Dostat malware vzorek z prostředí organizace na server k analýze, uložit ho
tak, aby se dal později dohledat, a vést o něm stopu, kdo ho poslal a odkud.

Analyzátor **není součástí**. To není nedodělek: příjem a analýza mají různé
nároky na dostupnost a různý poloměr škody, a mají proto zůstat oddělené i až
analyzátor přibude.

## Model hrozeb

Čemu se služba brání a čemu ne. Druhý sloupec je stejně důležitý jako první.

| hrozba | obrana |
|---|---|
| cizí nahrává vzorky | aplikační klíč ověřený u access-manageru |
| uniklý klíč | origin ACL — klíč mimo povolené sítě je bezcenný |
| klient si podvrhne adresu | `X-Real-IP` se bere jen od vlastní proxy |
| archiv zapíše mimo cílový adresář | kontrola výsledné cesty po `resolve()` |
| dekompresní bomba | tři nezávislé stropy |
| symlink v archivu ukáže do systému | symlinky/hardlinky/zařízení se přeskakují |
| vzorek se spustí | odebrání `x` bitu, `noexec` na mountech, `CapEff: 0` |
| podvržený formát archivu | rozhoduje suffix **i** magické bajty, ne jedno z nich |
| únik z procesu do systému | rootless kontejner, read-only kořen, mount jen na vault |
| únik z kontejneru na hostitele | `NoNewPrivileges` v unitu — `sudo`/`su`/`pkexec` ztrácejí účinek; `soc` není v sudoers |
| suid binárka jako nástroj útoku | obraz nemá žádnou; mounty jsou `nosuid,nodev,noexec` |
| vzorek se stáhne z internetu | vault leží mimo webroot |
| useknutý přenos projde jako platný | nepovinné `X-Expected-SHA256` |

**Čemu se nebrání:**

- **Vzorek se neanalyzuje ani neskenuje.** Uloží se, jaký přišel. Kdo ho
  z vaultu vezme, drží v ruce živý malware — to je účel, ne opomenutí.
- **Kompromitovaný klient uvnitř povoleného rozsahu** může posílat cokoli.
  Origin ACL omezuje odkud, ne kdo.
- **Odvolání klíče se projeví až po vypršení cache** (`SOC_AM_CACHE_S`,
  výchozí 30 s). Kompromis mezi kolem po síti u každého požadavku a rychlostí
  odvolání.
- **Zaplnění disku.** Retence není žádná a kvóta se nehlídá.
- **Někdo, kdo už na stroji legitimně je.** `NoNewPrivileges` platí pro
  procesy spuštěné unitem; shell získaný přes `sudo -iu soc` nebo ssh
  potomkem unitu není. Chrání to před únikem *ze služby*, ne před operátorem
  ani před kompromitovaným účtem s vlastním přístupem.

## Rozhodnutí

### Vzorek je adresovaný svým obsahem

Cesta ve vaultu je odvozená ze sha256. Z toho plyne všechno ostatní:
idempotence příjmu, nemožnost dvou různých obsahů na jedné cestě, přirozený
klíč pro dohledávání.

**Nebyla to snaha o idempotenci** — ta vyšla jako důsledek. Kdyby se vzorky
adresovaly pořadovým číslem nebo časem, musel by se duplicitní příjem řešit
zvlášť a špatně.

MD5 a SHA1 se počítají taky, protože v nich se vzorky mezi týmy běžně
dohledávají (VirusTotal, MISP). Identitou je ale sha256 — MD5 má praktické
kolize a jako adresa obsahu se nehodí.

### Dorozbalení při opakovaném příjmu

Duplicita normálně nic nemění. Jedinou výjimkou je archiv, který čekal na
heslo: když druhý pokus heslo přinese, **dorozbalí se**.

Stav rozbalení je vlastnost vzorku, ne požadavku. Nechat archiv ležet
nerozbalený jen proto, že jsme jeho obsah už jednou viděli, by bylo držení
se pravidla proti jeho smyslu.

### Duplicita vrací 200, ne 409

`409 Conflict` by tvrdil, že je něco v nepořádku. Není: poslat tentýž vzorek
podruhé je legitimní a pro klienta to znamená, že **retry po timeoutu je
bezpečný** — nemusí zjišťovat, jestli první pokus prošel.

Pokus se přesto zapíše do `access.log`. „Kdo poslal totéž znovu" je pro SOC
informace, ne šum.

### Selhání rozbalení není selhání příjmu

Archiv, který nejde rozbalit, se **uloží** a dostane stav. Návratový kód je
pořád `201`.

Originál je to hlavní; rozbalení je pohodlí navíc. Kdyby heslovaný archiv
skončil chybou, klient by ho zkoušel poslat znovu — a dopadlo by to stejně.

### Heslo se posílá, nehádá

Nabízelo se zkoušet konvenční `infected`. Zamítnuto: bylo by to hádání se
skrytým seznamem, které buď funguje, nebo tiše nefunguje a nikdo neví proč.

Heslo je proto **pole požadavku** (`password` v multipartu nebo JSONu).
Do hlavičky nepatří — skončilo by v logu každé proxy po cestě. U syrového
těla se tím pádem heslo poslat nedá, a to je záměr, ne opomenutí.

Nikam se neukládá: ani do manifestu, ani do access.logu vzorku, ani do
provozního logu.

Šifrovaný ZIP nese buď staré ZipCrypto, nebo AES (7-Zip, WinRAR). Standardní
`zipfile` umí jen to první a na AES spadne, proto `pyzipper` — jediná
závislost, kterou projekt má nad flask a waitress.

### Jen ZIP

Původně se přijímal i tar. Zúženo na ZIP, protože je to **jediný běžný
formát, který umí heslo** a zvládneme ho bez externích nástrojů. Dva formáty
znamenaly dvě cesty kódem, z nichž jedna heslo neuměla a musela to hlásit
zvláštním stavem.

Formát potvrzuje **suffix jména i magické bajty**. Rozdělení není zbytečné:
každá kontrola chytí jinou chybu — špatně pojmenovaný archiv (`.tgz`, co je
opravdu tar) i podvržený obsah (`.zip`, co je RAR). Suffix je tvrzení
klienta, magické bajty jsou fakt.

Odmítnuté formáty se pojmenovávají (`rar`, `7z`, `gzip`, …), i když je
nepřijímáme. Kdo pošle RAR, má se dozvědět že poslal RAR, ne že „to není
zip".

### Verdikt, ne relace

Služba nedrží žádnou session. Klient posílá klíč u každého požadavku.

To odpovídá modelu access-manageru („dostanete verdikt, ne relaci") a znamená,
že restart služby nikoho neodhlásí a odvolání klíče platí do 30 vteřin.

### Origin ACL patří access-manageru, ne nám

Mohli jsme filtrovat adresy sami. Nedělá se to, protože by pak byla pravidla
na dvou místech a jedno z nich by se zapomínalo měnit.

Access-manager to už umí a mění se to bez výměny klíče. Naše práce je jediná:
**přeposlat mu skutečnou adresu klienta** v `X-Forwarded-For`. Bez toho by
měřil adresu našeho serveru a ACL by neznamenal nic.

Cena je nutnost správně nastavit, komu se hlavička věří — což je zároveň
nejzrádnější místo celého nasazení, protože špatná hodnota se neprojeví
chybou, jen tichou ztrátou rozlišování. Proto to u každého odmítnutí končí
v logu.

### Kontejner kvůli izolaci, ne přenositelnosti

Služba rozbaluje cizí, záměrně škodlivý archiv. Mount je tvrdší hranice než
`ReadWritePaths` v systemd unitu: hostitelský strom uvnitř **neexistuje**,
místo aby byl jen zakázaný.

K tomu `--cap-drop ALL`, `--read-only`, `--tmpfs /tmp` s `noexec` a rootless
podman — proces, který by z kontejneru utekl, je venku uid `300000+`, které
nikomu nepatří.

### Zpevnění ve dvou vrstvách, ne v jedné

Kontejnerové přepínače chrání *uvnitř*. Kdyby je někdo prolomil, stojí na
hostiteli jako `soc` — a tam začíná druhá vrstva: `NoNewPrivileges=yes`
v systemd unitu, které suid binárkám (`sudo`, `su`, `pkexec`) sebere účinek,
plus účet mimo sudoers se zamčeným heslem.

Obě vrstvy dělají v podstatě totéž na dvou různých místech, a to je záměr:
každá z nich se dá jednou úpravou omylem vypnout, obě naráz spíš ne.

### Konfigurace prostředím, ne souborem

Access-manager má `conf.d/` a montuje ho do kontejneru. soc-api ne — má míň
parametrů a všechny jsou skalární.

Důsledek: `reload` nedává smysl, změna parametru znamená restart. U služby
bez relací je restart levný.

### Vault mimo webroot

Na téže doméně běží statický web. Kdyby vault ležel pod `public_html`, byl
by **každý přijatý malware vzorek stažitelný z internetu** — a nikdo by si
toho nevšiml, dokud by to někdo nezkusil.

Je to jednořádkové rozhodnutí s neúměrným dopadem, proto je zmíněné
v konfiguraci, ve vzoru nginx i v ověřovacím postupu.

### Retence žádná

Nabízelo se mazat po 90 dnech (shodně s auditní stopou access-manageru).
Zamítnuto: smazaný vzorek nejde vrátit a rozhodnutí, jak dlouho je držet,
je provozní a právní, ne technické.

Výchozí stav je proto ten, který nic neztrácí.

### Stav v manifestu od začátku

`state` a `analysis.state` jsou v manifestu, i když analyzátor neexistuje.

Přidat později **hodnotu** do existujícího pole je zpětně kompatibilní.
Přidat **pole** by znamenalo, že klienti napsaní dnes o něm nevědí. Levnější
je pole vyrobit teď, prázdné.

## Co se nepovedlo napoprvé

Dvě chyby, které stojí za zaznamenání, protože se dají zopakovat.

**Werkzeug a vyčerpaný stream.** Podmínka `if "file" in request.files`
spustila lazy parsování formuláře a tím vyčerpala `request.stream`. U
`curl --data-binary` (posílá `x-www-form-urlencoded`) došlo do vaultu prázdné
tělo. Oprava: na `request.files` sahat jen u skutečného multipartu.

**Test, který nic nedokázal.** Ověření, že se věří `X-Real-IP`, probíhalo
požadavkem ze stejného stroje, kde služba běží — `peer` i skutečná adresa
klienta byly tatáž hodnota, takže obě možná chování daly stejný výsledek.
Rozlišil to až požadavek s `X-Real-IP`, které se od `peer` liší.

Obojí je v [kod.md](kod.md) u příslušného místa, aby to při úpravách nikdo
nevrátil.

## Co by přišlo dál

- **Analyzátor** mimo požadavek, výsledek do `analysis` v manifestu.
- **Kvóta a hlídání místa** — dnes se nehlídá nic.
- **Uživatelé místo jen aplikačních klíčů**, až bude API ovládat člověk;
  access-manager na to má TOTP a `Access.remote`.
- **Testy HTTP vrstvy** přes `app.test_client()` s podstrčeným `_whoami`.
