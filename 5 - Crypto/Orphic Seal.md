# Orphic Seal

- **Catégorie :** crypto — 255 points
- **CTF :** Hack Ton Lycée (HTL 2026, plateforme Yogosha)
- **Service :** `http://crypto.ctf.yogosha.com:9001`
- **Flag :** `HTL{one_unhashed_commitment_breaks_the_proof}`

## Énoncé

> Orphic Seal délivre des credentials anonymes sur un groupe d'ordre premier. Pour
> s'enrôler, on fournit une preuve de Schnorr « OR » non-interactive de la connaissance
> du log discret de **l'une** des clés d'émetteur `Y_1 .. Y_N`, sans révéler laquelle.
> Une preuve valide délivre un credential ; un credential admin présenté à `/mint` donne
> le flag. Il y a aussi `/revoke`. **Une de ces deux portes s'ouvre plus facilement que
> prévu** — choisissez la bonne cible.

## Protections / modèle

- Groupe des résidus quadratiques modulo le safe prime MODP 2048 bits de la RFC 3526,
  d'ordre premier `Q = (P-1)/2`, générateur `G`.
- `N = 8` clés émetteur `Y_i = G^{x_i}`, les secrets `x_i` restant côté serveur.
- Preuve OR de Cramer–Damgård–Schoenmakers rendue non-interactive par Fiat–Shamir.
  Le vérifieur (`orproof.verify`) :
  1. recalcule chaque engagement `R_i = G^{s_i} · Y_i^{-c_i}` ;
  2. calcule un challenge de transcript `H(transcript)` ;
  3. accepte **ssi** `sum_i c_i ≡ H(transcript) (mod Q)`.
- Le credential est un blob `base64(body) . base64(HMAC-SHA256(body))` : infalsifiable
  sans la clé `CRED_KEY`. On ne l'attaque donc pas — on le fait **émettre** légitimement.

## La vulnérabilité

La sécurité (soundness) d'une preuve OR de Schnorr repose sur le fait que le challenge
Fiat–Shamir lie **TOUS** les engagements `R_i`. Si un seul `R_i` n'entre pas dans le
hash, il devient une variable libre et on peut forger une preuve **sans connaître aucun
secret**.

Or, dans `orproof.py`, la fonction utilisée par l'enrôlement oublie le dernier engagement :

```python
def enroll_challenge(domain, ys, rs):
    n = len(ys)
    h = hashlib.sha512()
    h.update(domain)
    for i in range(n):
        h.update(_field(encode(ys[i])))
    for i in range(n - 1):            # <--- BUG : s'arrête à n-1, R_{n-1} N'EST PAS haché
        h.update(_field(encode(rs[i])))
    return scalar_from_hash(h.digest())
```

À comparer avec la version de révocation, qui, elle, hache bien les `n` engagements :

```python
def revoke_challenge(domain, ys, rs):
    ...
    for i in range(n):                # tous les R_i sont liés -> /revoke est sain
        h.update(_field(encode(rs[i])))
```

Donc **`/enroll` est la porte faible.** Comme `R_{N-1}` n'intervient jamais dans le
challenge, on choisit librement `c_{N-1}` pour satisfaire `sum c_i == expected`, et
`s_{N-1}` peut valoir n'importe quoi.

## Résolution pas à pas

**1. Récupérer les paramètres** (groupe, clés émetteur, domaine d'enrôlement) via
`GET /params`.

```python
p   = GET /params
P, Q, G = int(p["p"],16), int(p["q"],16), int(p["g"],16)
N   = p["n"]                       # 8
ys  = [int(y,16) for y in p["issuer_keys"]]
domain = p["domain_enroll"].encode()
```

**2. Clauses « bidon » pour i = 0 .. N-2.** On pose `c_i = s_i = 0`. Le vérifieur
recalcule alors `R_i = G^0 · Y_i^{0} = 1` pour ces indices.

```python
c = [0]*N; s = [0]*N
rs = [1]*N                         # R_i = 1 pour i < N-1 (ce que recalculera le serveur)
```

**3. Calculer le challenge comme le fait le serveur** — en n'incluant que `R_0..R_{N-2}`
(exactement le bug). L'encodage est `len(x):4 || x` sur des éléments de `ELEMENT_BYTES`
octets, hash SHA-512 réduit mod Q.

```python
def encode(x): return (x % P).to_bytes((P.bit_length()+7)//8, "big")
def field(b):  return len(b).to_bytes(4,"big") + b

h = sha512(); h.update(domain)
for y in ys:            h.update(field(encode(y)))
for i in range(N-1):    h.update(field(encode(rs[i])))   # R_{N-1} exclu
expected = int.from_bytes(h.digest(), "big") % Q
```

**4. Fermer l'égalité avec la dernière clause.** `R_{N-1}` n'étant pas haché, on l'utilise
pour absorber la somme :

```python
c[N-1] = expected % Q              # sum(c) == H(transcript)
s[N-1] = 0                         # R_{N-1} = G^0 · Y_{N-1}^{-c} : jamais vérifié
```

**5. Enrôler puis mint.** La preuve passe, on reçoit un credential `admin:True`, puis
`/mint` renvoie le flag.

```python
cred = POST /enroll {"c":[hex...], "s":[hex...]}
flag = POST /mint   {"credential": cred}
```

## Script complet -> Script intégral

Autonome (bibliothèque standard uniquement), lançable par
`python3 solve.py crypto.ctf.yogosha.com 9001`.

```python
#!/usr/bin/env python3
"""Orphic Seal - forge an enrolment OR-proof (the enroll transcript fails to
bind the last commitment R_{N-1}, so soundness is broken; no witness needed).
Usage: python3 solve.py <host> <port>   (defaults: crypto.ctf.yogosha.com 9001)
"""
import sys, json, hashlib, urllib.request, urllib.error

def jget(url):
    return json.load(urllib.request.urlopen(url))

def jpost(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return json.load(e)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "crypto.ctf.yogosha.com"
    port = sys.argv[2] if len(sys.argv) > 2 else "9001"
    base = f"http://{host}:{port}"

    p = jget(base + "/params")
    P = int(p["p"], 16); Q = int(p["q"], 16); G = int(p["g"], 16)
    N = p["n"]; domain = p["domain_enroll"].encode()
    ys = [int(y, 16) for y in p["issuer_keys"]]
    elem_bytes = (P.bit_length() + 7) // 8

    def encode(x): return (x % P).to_bytes(elem_bytes, "big")
    def field(b): return len(b).to_bytes(4, "big") + b

    # trivial clauses 0..N-2: c_i = s_i = 0  ->  R_i = G^0 * Y_i^0 = 1
    c = [0] * N; s = [0] * N
    rs = [1] * N                                    # R_i the verifier recomputes for i<N-1

    # enroll_challenge hashes domain, all Y_i, then only R_0..R_{N-2} (R_{N-1} unbound!)
    h = hashlib.sha512(); h.update(domain)
    for y in ys: h.update(field(encode(y)))
    for i in range(N - 1): h.update(field(encode(rs[i])))
    expected = int.from_bytes(h.digest(), "big") % Q

    c[N - 1] = expected % Q                          # make sum(c) == H(transcript)
    s[N - 1] = 0                                     # R_{N-1} is never hashed -> free

    proof = {"c": [format(x, "x") for x in c], "s": [format(x, "x") for x in s]}
    r = jpost(base + "/enroll", proof)
    cred = r["credential"]
    out = jpost(base + "/mint", {"credential": cred})
    print(out.get("flag") or out)

if __name__ == "__main__":
    main()
```

## Test

Testé en local en important `group.py`/`orproof.py` avec des clés émetteur aléatoires :
la preuve forgée passe `verify(DOMAIN_ENROLL, ...) == True`, et la **même** astuce échoue
sur `verify(DOMAIN_REVOKE, ...) == False` (ce qui confirme que seule l'enrôlement est
cassée). Exécuté ensuite contre le service live :

```
HTL{one_unhashed_commitment_breaks_the_proof}
```
