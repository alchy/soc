"""Domena autentizace a autorizace.

    provider.py        rozhrani AuthProvider + modely Identity / AuthResult
    mock.py            MockAuthProvider (jindrich/demo) pro vyvoj a demo
    access_manager.py  AccessManagerAuthProvider - realny TOTP proti access-manageru
    session.py         nase server-side session (podepsana cookie, abs + idle TTL)
    authz.py           brana: autentizace != autorizace (clenstvi ve skupine)

Zamena mock <-> realny provider je jeden radek v build_provider() (viz app.py),
takze cely portal se da postavit a otestovat drive, nez mame klic k AM.
"""
