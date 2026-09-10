# Obraz sluzby. Stavi se z korene repozitare:
#
#     deploy/container-build.sh          (nebo: podman build -t soc-api .)
#
# V obrazu NENI vault ani konfigurace. Vault se montuje zvenci a je jediny
# zapisovatelny adresar, ktery sluzba ma - to je hlavni duvod, proc tahle
# sluzba bezi v kontejneru. Rozbaluje cizi malware; mount je tvrdsi hranice
# nez ReadWritePaths v systemd unitu.
FROM python:3.12-slim

# UID natvrdo: rootless podman mapuje hostitelskeho uzivatele na tohle cislo
# pres --userns=keep-id:uid=1000,gid=1000. Kdyby se UID posunulo, prava na
# namontovanem vaultu prestanou sedet.
RUN useradd --create-home --uid 1000 soc

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY soc_api ./soc_api
RUN pip install --no-cache-dir .

# Obrazu setrit netreba: nic z toho sluzba nepotrebuje a kazda z nich je
# nastroj navic pro toho, kdo by uvnitr dostal shell. `--security-opt
# no-new-privileges` je uz zvednout nenecha, ale tohle je druha vrstva -
# kdyby prvni nekdo pri uprave container-run.sh vypnul.
#
#   /usr/bin/su, mount, umount, passwd, newgrp, chsh, chfn, gpasswd,
#   chage, expiry, /usr/sbin/unix_chkpwd
RUN find / -xdev -perm /6000 -type f -exec chmod -s {} + 2>/dev/null || true

COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh

# Vault zalozit uz tady a rovnou uzivateli sluzby: anonymni svazek podle
# VOLUME dedi vlastnictvi z obrazu, a kdyby patril rootovi, `soc` by do nej
# nezapsal. 0700 drzi uloziste stejne samo, tohle je vychozi stav.
RUN install -d -o soc -g soc -m 0700 /var/lib/soc/vault \
 && chmod +x /usr/local/bin/entrypoint.sh

USER soc
VOLUME /var/lib/soc/vault
EXPOSE 8095

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8095/api/v1/healthz')"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD []
