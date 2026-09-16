"""soc-portal - webove okno SOC tymu do analyzovanych vzorku.

Vrstvy (vertikalni rez, jadro nezna HTTP):

    web/            prezentace - tenka slupka nad Flaskem (routy, sablony)
    auth/           domena autentizace - providery, session, autorizace
    vault_reader    domena dat - READ-ONLY cteni vaultu (zrcadli soc_api.storage)
    config          vsechny volby z prostredi, zadne magicke hodnoty v kodu

Portal do vaultu nikdy nezapisuje; mount je read-only i na urovni kontejneru.
"""
