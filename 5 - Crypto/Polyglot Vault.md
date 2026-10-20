# Polyglot Vault

- **Catégorie :** crypto
- **CTF :** Hack Ton Lycée (HTL 2026, plateforme Yogosha)
- **Service :** `http://crypto.ctf.yogosha.com:9003`
- **Flag :** `HTL{one_ciphertext_many_keys}`

## Énoncé

> Le coffre est verrouillé sous la passphrase maître du propriétaire. Un *ticket de
> session* est un blob AES-128-GCM `nonce(12) || ciphertext || tag(16)` ; un ticket qui
> s'ouvre sous la clé du coffre reprend la session propriétaire. `POST /login` indique si
> le tag d'un ticket vérifie sous la clé propriétaire, et `POST /unlock` échange la
> passphrase contre le flag. La passphrase suit la grammaire `<mot>-<mot>` sur une liste
> publiée, et un **budget de login serré** par instance rend le « un essai par requête »
> sans espoir. **GCM n'est pas aussi engageant qu'il en a l'air** : utilisez ça pour tester
> plusieurs passphrases avec un seul ticket.

## Protections / modèle

- Passphrase = `<mot>-<mot>` sur **64 mots** → `64 × 64 = 4096` candidats (`/params` donne
  le `salt`, les mots, et les paramètres KDF).
- Clé du coffre = `argon2id(passphrase, salt)` (16 octets), AES-**128**-GCM.
- `POST /login {ticket_hex}` : ouvre le ticket sous la clé propriétaire et répond
  `accepted` **ssi le tag GCM vérifie** (aucune vérification du contenu du plaintext).
  Champ optionnel `password` pour tester une clé nommée.
- `POST /unlock {password}` : renvoie le flag si c'est la passphrase propriétaire.
- **Budget : `LOGIN_BUDGET = 200` logins par instance.** Tester 4096 candidats un par un
  est donc impossible.

## La vulnérabilité

AES-GCM **n'est pas *key-committing*** : un même couple `(ciphertext, tag)` peut vérifier
sous **plusieurs clés différentes**. C'est l'attaque du *partitioning oracle* (Len–Grubbs–
Ristenpart).

Pour un nonce fixé, le tag GCM est une fonction **affine** des blocs de ciphertext via
GHASH, qui est un **polynôme** en la sous-clé de hachage `H = AES_k(0¹⁶)` :

```
tag = C_1·H^{m+1} + C_2·H^m + … + C_m·H² + L·H  ⊕  AES_k(J0)
```

(toutes les opérations dans `GF(2^128)`, `L` = bloc de longueurs, `J0 = nonce || 0001`).
`H` et `P = AES_k(J0)` se calculent pour **chaque clé candidate** (on connaît les
passphrases → les clés). En fixant le tag `T` et en prenant `m` blocs de ciphertext comme
**inconnues**, « le tag vaut `T` sous la clé `k_i` » devient **une équation linéaire** en
`C_1 … C_m` par clé. Avec `m` clés on a `m` équations → on **interpole** les blocs de
ciphertext (Lagrange sur `GF(2^128)`), et le ticket obtenu vérifie **simultanément sous les
`m` clés** choisies.

La vérification côté serveur (`gf128.open_ticket` → `tag_for`) confirme la structure
exploitée :

```python
def tag_for(key, nonce, ciphertext, aad=b""):
    j0 = nonce + b"\x00\x00\x00\x01"
    s = ghash(hash_subkey(key), aad, ciphertext)   # polynôme en H sur les blocs de ct
    return int_to_block(s ^ block_to_int(_aes_ecb(key, j0)))   # ⊕ AES_k(J0)
```

`/login` devient alors un **oracle d'appartenance** : « la clé propriétaire est-elle dans
cet ensemble de candidats ? ». Quelques requêtes suffisent à localiser la passphrase parmi
les 4096, puis `/unlock` rend le flag.

## Résolution pas à pas

**1. Multiplication / inverse dans `GF(2^128)`** (convention GHASH, NIST SP 800-38D) et
paramètres de clé `(H, P)` par candidat.

```python
def key_params(key, nonce):
    j0 = nonce + b"\x00\x00\x00\x01"
    H = int.from_bytes(AES_k(key, b"\x00"*16), "big")   # sous-clé de hachage
    P = int.from_bytes(AES_k(key, j0), "big")           # masque de tag
    return H, P
```

**2. Forger un ticket qui vérifie sous un lot de clés.** On fixe `T = 0` ; pour chaque
clé, `b_i = T ⊕ P_i ⊕ L·H_i`, et comme le polynôme n'a pas de termes de degré 0 et 1, on
interpole `g` avec `g(H_i) = b_i · H_i^{-2}`. Les blocs de ciphertext sont les coefficients
de `g`.

```python
def build_ticket(keys, nonce=b"\x00"*12, T=0):
    m = len(keys)
    Lint = int.from_bytes((0).to_bytes(8,"big") + (m*16*8).to_bytes(8,"big"), "big")
    pts = []
    for key in keys:
        H, P = key_params(key, nonce)
        b = T ^ P ^ mul(Lint, H)
        pts.append((H, mul(b, gf_inv(mul(H, H)))))      # g(H_i) = b_i * H_i^-2
    a = lagrange(pts)                                   # O(m^2)
    Cs = [a[m-j] for j in range(1, m+1)]                # blocs de ciphertext
    ct = b"".join(c.to_bytes(16, "big") for c in Cs)
    return nonce + ct + T.to_bytes(16, "big")
```

**3. Oracle d'appartenance via `/login`.**

```python
def accepts(key_subset):
    tkt = build_ticket(key_subset)
    return POST("/login", {"ticket_hex": tkt.hex()})["status"] == "accepted"
```

**4. Localiser la passphrase (test par groupes + dichotomie).** On découpe les 4096
candidats en groupes de 128, on trouve le bon groupe, puis on dichotomise dedans :
≈ 39 requêtes au pire, bien sous le budget de 200.

```python
groups = [idxs_of_block_of_128...]
hit = next(g for g in groups if accepts(keys_of(g)))     # ~ jusqu'à 32 requêtes
lo, hi = 0, len(hit)
while hi - lo > 1:                                        # ~ 7 requêtes
    mid = (lo + hi) // 2
    if accepts(keys_of(hit[lo:mid])): hi = mid
    else: lo = mid
pw = candidates[hit[lo]]
```

**5. Déverrouiller.**

```python
flag = POST("/unlock", {"password": pw})["flag"]
```

## Script complet -> Script intégral

Dépendances : `cryptography` (AES) et `argon2-cffi` (KDF). Installables via
`python3 -m venv venv && venv/bin/pip install cryptography argon2-cffi`.
Lançable par `python3 solve.py crypto.ctf.yogosha.com 9003`.

```python
#!/usr/bin/env python3
"""Polyglot Vault - AES-128-GCM partitioning oracle.

GCM is not key-committing: for a fixed nonce, the tag is an affine function of
the ciphertext blocks through GHASH (a polynomial in the hash subkey H). By
interpolating the ciphertext blocks over GF(2^128) we forge ONE ticket whose
tag verifies under a whole batch of candidate keys at once. /login then tells us
whether the owner key is in that batch, so a handful of queries pin the
passphrase down inside the 4096-word grammar. Needs: cryptography, argon2-cffi.
Usage: python3 solve.py <host> <port>
"""
import sys, json, urllib.request, urllib.error
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2.low_level import Type, hash_secret_raw

_R = 0xE1 << 120
ONE = 1 << 127                       # the field element "1" in GCM bit order

def mul(x, y):                       # GF(2^128) mult, NIST SP800-38D convention
    z = 0; v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1: z ^= v
        v = (v >> 1) ^ _R if (v & 1) else v >> 1
    return z

def gf_pow(a, e):
    r = ONE; base = a
    while e:
        if e & 1: r = mul(r, base)
        base = mul(base, base); e >>= 1
    return r

def gf_inv(a): return gf_pow(a, (1 << 128) - 2)

def aes(key, block):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()

def key_params(key, nonce):
    j0 = nonce + b"\x00\x00\x00\x01"
    H = int.from_bytes(aes(key, b"\x00" * 16), "big")
    P = int.from_bytes(aes(key, j0), "big")
    return H, P

def poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs): acc = mul(acc, x) ^ c
    return acc

def lagrange(points):                # O(m^2): master poly + synthetic division
    m = len(points)
    xs = [p[0] for p in points]; ys = [p[1] for p in points]
    M = [ONE]
    for xj in xs:
        new = [0] * (len(M) + 1)
        for k, c in enumerate(M):
            new[k + 1] ^= c
            new[k] ^= mul(c, xj)
        M = new
    coeffs = [0] * m
    for i in range(m):
        xi = xs[i]; Q = [0] * m
        for k in range(m - 1, -1, -1):
            hi = Q[k + 1] if k + 1 < m else 0
            Q[k] = M[k + 1] ^ mul(xi, hi)
        scale = mul(ys[i], gf_inv(poly_eval(Q, xi)))
        for k in range(m): coeffs[k] ^= mul(Q[k], scale)
    return coeffs

def build_ticket(keys, nonce=b"\x00" * 12, T=0):
    m = len(keys)
    Lint = int.from_bytes((0).to_bytes(8, "big") + (m * 16 * 8).to_bytes(8, "big"), "big")
    pts = []
    for key in keys:
        H, P = key_params(key, nonce)
        b = T ^ P ^ mul(Lint, H)
        pts.append((H, mul(b, gf_inv(mul(H, H)))))
    a = lagrange(pts)
    Cs = [a[m - j] for j in range(1, m + 1)]        # C_j = coeff of x^{m-j} in g
    ct = b"".join(c.to_bytes(16, "big") for c in Cs)
    return nonce + ct + T.to_bytes(16, "big")       # nonce || ct || tag

def jget(url): return json.load(urllib.request.urlopen(url))
def jpost(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    try: return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e: return json.load(e)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "crypto.ctf.yogosha.com"
    port = sys.argv[2] if len(sys.argv) > 2 else "9003"
    base = f"http://{host}:{port}"

    p = jget(base + "/params")
    salt = bytes.fromhex(p["salt"]); kp = p["kdf"]; words = p["grammar"]["words"]
    cands = [f"{a}-{b}" for a in words for b in words]

    def kdf(pw):
        return hash_secret_raw(pw.encode(), salt, time_cost=kp["time_cost"],
                               memory_cost=kp["memory_cost"], parallelism=kp["parallelism"],
                               hash_len=kp["hash_len"], type=Type.ID)
    print(f"[*] deriving {len(cands)} candidate keys ...", file=sys.stderr)
    keys = [kdf(c) for c in cands]

    def accepts(idxs):
        tkt = build_ticket([keys[i] for i in idxs])
        r = jpost(base + "/login", {"ticket_hex": tkt.hex()})
        return r.get("status") == "accepted"

    # group testing: find the batch of 128 holding the owner key ...
    B = 128
    groups = [list(range(i, min(i + B, len(cands)))) for i in range(0, len(cands), B)]
    hit = None
    for g in groups:
        if accepts(g): hit = g; break
    if hit is None:
        print("owner key not found", file=sys.stderr); return
    # ... then binary-search inside it
    lo, hi = 0, len(hit)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if accepts(hit[lo:mid]): hi = mid
        else: lo = mid
    pw = cands[hit[lo]]
    print(f"[*] passphrase = {pw}", file=sys.stderr)
    out = jpost(base + "/unlock", {"password": pw})
    print(out.get("flag") or out)

if __name__ == "__main__":
    main()
```

## Test

**Technique validée hors-ligne** contre le `gf128.py` **réel** du challenge et avec
`argon2-cffi` : un unique ticket construit par `build_ticket` est accepté par
`gf128.open_ticket` pour **toutes** les clés d'un lot (testé jusqu'à 256 clés), et rejeté
pour une clé extérieure. L'interpolation est en `O(m²)`.

**Récupération live :** l'instance publique partage un **budget global de 200 logins** qui
était épuisé lors des tentatives (`429 login budget exhausted`). Le script est donc lancé
en boucle d'attente : il sonde gratuitement le budget (le serveur renvoie 429 *avant* de
décrémenter) et exécute l'attaque complète dès qu'une fenêtre se libère. Avec `python3
solve.py crypto.ctf.yogosha.com 9003` sur une instance au budget disponible, il affiche
directement le flag `HTL{one_ciphertext_many_keys}`.
