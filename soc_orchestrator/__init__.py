"""soc-orchestrator — analytická komponenta SOC systému (třetí proces).

Bere hotové vzorky z vaultu (`manifest.analysis.state == pending`), pustí na ně
sdílenou knihovnu `soc_mail` a výsledek zapíše jako `analysis.json` do složky
vzorku. Běží jako jednoduchá smyčka: reclaim → zpracuj pending → heartbeat →
sleep. Jediný zapisovatel analýzy; portál a soc_api ji jen čtou/servírují.

RW k vaultu; atomický zápis (temp + rename) je invariant sdílený se soc_api.
"""
