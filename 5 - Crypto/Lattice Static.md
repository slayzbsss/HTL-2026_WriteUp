# Lattice Static

- **Catégorie :** crypto
- **CTF :** Hack Ton Lycée (HTL 2026, plateforme Yogosha)
- **Service :** `http://crypto.ctf.yogosha.com:9002`
- **Flag :** `HTL{the_fo_check_leaks_every_coefficient}`

## Énoncé

> Un KEM module-LWE fait maison sur `R_q = Z_q[x]/(x^n+1)` emballe une clé au démarrage,
> et le flag est scellé sous le secret partagé avec un chiffrement par flot authentifié.
> On reçoit la clé publique et le flag scellé. Un endpoint de décapsulation prend un
> chiffré et dit **s'il se décapsule proprement** — et ce simple bit est bien plus
> généreux qu'il n'y paraît. Les paramètres sont sur-mesure : lisez ceux fournis.

## Protections / modèle

- KEM module-LWE façon LPR sur `R_q = Z_q[x]/(x^n+1)`, paramètres de `kem.py` :
  `n = 128`, `k = 3`, `q = 3457`, bruit CBD `η = 2`, encodage d'un bit = `⌈q/2⌉ = 1729`.
- `GET /pk` : paramètres + clé publique. `GET /flag_ct` : le flag scellé
  (`ct` KEM `{u, v, tag}` + `box` AEAD).
- `POST /decap {u, v, tag}` : calcule `m' = decode(v − sᵀu)`, puis **accepte ssi
  `H(m') == tag`** (c'est le re-encryption tag, une vérification « façon Fujisaki–Okamoto »).
- Le flag est scellé par un flot maison : `box = nonce(16) || ct || HMAC-SHA256`, clé
  `K = KDF(m)` où `m` est le message KEM du flag.
- Rate-limit : 2000 requêtes / 60 s (large).

## La vulnérabilité

Le `tag` est **soumis par nous**, et l'oracle accepte ssi `H(decode(v − sᵀu)) == tag`.
Comme `H` est publique, choisir `tag = H(m*)` transforme `/decap` en un **oracle
d'égalité exact** :

> « est-ce que `decode(v − sᵀu)` vaut exactement le message `m*` que j'ai choisi ? »

C'est un *plaintext-checking oracle* (PC-oracle), et il fait fuiter la clé secrète `s`
coefficient par coefficient. Code concerné dans `kem.decaps` :

```python
def decaps(sk, ct):
    w = poly_sub(v, vec_dot(sk.s, u))     # w = v - s^T u
    m = decode(w)
    recomputed = tag(m)                   # H(m') recalculé
    claimed = bytes.fromhex(ct["tag"])    # ... comparé au tag QUE NOUS FOURNISSONS
    if not _equal(recomputed, claimed):
        return False, b""
    return True, kdf(m)
```

**L'astuce du coefficient unique.** On choisit `u` nul partout sauf `u[t] = [c, 0, …, 0]`
(polynôme constant `c`). Comme la multiplication par un polynôme constant est une mise à
l'échelle coordonnée par coordonnée :

```
w_i = v_i − c · (s_t)_i   (mod q)   pour toute coordonnée i
```

Les coefficients du secret sont **minuscules** (CBD η=2 ⇒ valeurs dans `{-2,-1,0,1,2}`).
En prenant `c = 345` (donc `2c = 690 < q/4 = 864`), toutes les coordonnées `v_j = 0`
donnent `w_j = −c·(s_t)_j` qui **décode toujours à 0**. On force ainsi tout le vecteur à 0
sauf la coordonnée visée. Sur la coordonnée `i`, on règle `v_i` pour que le bit décodé
bascule selon un **seuil** sur `(s_t)_i` : trois requêtes (recherche dichotomique sur 5
valeurs) suffisent à déterminer chaque coefficient.

Une fois `s` entièrement reconstruit, on déchiffre le flag : `w = v_flag − sᵀu_flag`,
`m = decode(w)`, `K = KDF(m)`, puis on ouvre la `box`.

## Résolution pas à pas

Décodage : bit = 1 ssi `q/4 ≤ (w mod q) < 3q/4`, soit `lo = 864`, `hi = 2592`.

**1. Oracle de test de seuil.** `test(t, i, th)` renvoie `True` ssi `(s_t)_i ≤ th`.
On place `v_i` au milieu de la fenêtre pour le seuil `th`, le reste à 0, et on vise
`m* = e_i` (vecteur unité au bit `i`).

```python
C = 345
def test(t, i, th):
    u = [[0]*N for _ in range(K)]
    u[t] = [C] + [0]*(N-1)                 # w = v - c*s_t  (coordonnée par coordonnée)
    v = [0]*N
    v[i] = (lo + C//2 + C*th) % Q          # bit_i = 1  <=>  (s_t)_i <= th
    m = [0]*N; m[i] = 1
    return decap(u, v, tag(m)) == "ok"     # accepte ssi decode(w) == e_i
```

**2. Un coefficient = 3 requêtes.** Recherche du plus petit seuil validé parmi
`{-2,-1,0,1}` ; si aucun, la valeur est `2`.

```python
def coeff(t, i):
    for th in (-2, -1, 0, 1):
        if test(t, i, th):
            return th
    return 2
```

**3. Reconstruire tout `s`** (K·n = 384 coefficients, ~1100 requêtes au total).

```python
s = [[coeff(t, i) % Q for i in range(N)] for t in range(K)]
```

**4. Déchiffrer le flag.** `w = v_flag − sᵀu_flag`, `m = decode(w)`, `K = KDF(m)`, puis
on ouvre la `box` (vérif HMAC + XOR du flot SHA-256).

```python
w = v_flag - s^T u_flag ;  m = decode(w) ;  K = kdf(m)
flag = open_box(K, box)
```

## Script complet -> Script intégral

Autonome, **bibliothèque standard uniquement** (toute la crypto client est réimplémentée).
Lançable par `python3 solve.py crypto.ctf.yogosha.com 9002` (~70 s).

```python
#!/usr/bin/env python3
"""Lattice Static - plaintext-checking (decapsulation) oracle key recovery.

The /decap endpoint accepts iff H(decode(v - s^T u)) equals the tag we submit,
i.e. it is an exact "does decode(v - s^T u) == m*?" oracle. Feeding u = (0,..,
[c,0..],..,0) makes w = v - c*s_t coefficient-wise; small c keeps every other
coordinate decoding to 0, so one query tests a threshold on a single secret
coefficient (which lives in {-2..2}). Recover s, then open the sealed flag.
Pure standard library.  Usage: python3 solve.py <host> <port>
"""
import sys, json, hashlib, hmac, http.client, base64

DOM_TAG = b"lattice-static/tag/v1"
DOM_KEY = b"lattice-static/key/v1"
DOM_STREAM = b"lattice-static/stream/v1"
DOM_MAC = b"lattice-static/mac/v1"

class Client:
    def __init__(self, host, port):
        self.host, self.port = host, int(port)
        self.conn = http.client.HTTPConnection(host, int(port), timeout=30)
    def _req(self, method, path, body=None):
        hdr = {"Content-Type": "application/json"} if body is not None else {}
        data = json.dumps(body).encode() if body is not None else None
        for _ in range(3):
            try:
                self.conn.request(method, path, data, hdr)
                return json.loads(self.conn.getresponse().read())
            except Exception:
                self.conn.close()
                self.conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        raise RuntimeError("request failed")
    def get(self, path): return self._req("GET", path)
    def post(self, path, obj): return self._req("POST", path, obj)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "crypto.ctf.yogosha.com"
    port = sys.argv[2] if len(sys.argv) > 2 else "9002"
    cl = Client(host, port)

    pk = cl.get("/pk")
    N, K, Q = pk["n"], pk["k"], pk["q"]
    lo, hi = Q // 4, (3 * Q) // 4
    C = 345                                  # 2C < lo, so non-target coords decode 0

    # ---- ring helpers (negacyclic) and the server's tag/kdf/AEAD, reimplemented ----
    def bits_to_bytes(bits):
        out = bytearray(N // 8)
        for i, b in enumerate(bits):
            if b & 1: out[i >> 3] |= 1 << (i & 7)
        return bytes(out)
    def tag(bits): return hashlib.sha256(DOM_TAG + bits_to_bytes(bits)).digest()
    def kdf(bits):  return hashlib.sha256(DOM_KEY + bits_to_bytes(bits)).digest()
    def poly_mul(a, b):
        res = [0] * N
        for j in range(N):
            bj = b[j]
            if not bj: continue
            for i in range(N):
                k = i + j
                if k < N: res[k] += a[i] * bj
                else:     res[k - N] -= a[i] * bj
        return [x % Q for x in res]
    def decode(poly): return [1 if lo <= (c % Q) < hi else 0 for c in poly]

    # ---- PC oracle ----
    def test(t_idx, i, th):
        u = [[0] * N for _ in range(K)]
        u[t_idx] = [C] + [0] * (N - 1)
        v = [0] * N
        v[i] = (lo + C // 2 + C * th) % Q
        m = [0] * N; m[i] = 1
        r = cl.post("/decap", {"u": u, "v": v, "tag": tag(m).hex()})
        return r.get("status") == "ok"
    def coeff(t_idx, i):
        for th in (-2, -1, 0, 1):
            if test(t_idx, i, th): return th
        return 2

    s = [[0] * N for _ in range(K)]
    for t_idx in range(K):
        for i in range(N):
            s[t_idx][i] = coeff(t_idx, i) % Q

    # ---- recover the flag ----
    fc = cl.get("/flag_ct")
    u = [[c % Q for c in row] for row in fc["ct"]["u"]]
    v = [c % Q for c in fc["ct"]["v"]]
    acc = [0] * N
    for sp, up in zip(s, u):
        pm = poly_mul(sp, up)
        acc = [(a + b) % Q for a, b in zip(acc, pm)]
    w = [(v[i] - acc[i]) % Q for i in range(N)]
    m_flag = decode(w)
    key = kdf(m_flag)

    box = base64.b64decode(fc["box"])
    nonce, ct, mac = box[:16], box[16:-32], box[-32:]
    exp = hmac.new(key, DOM_MAC + nonce + ct, hashlib.sha256).digest()
    assert hmac.compare_digest(mac, exp), "MAC check failed - secret recovery wrong"
    out = bytearray(); counter = 0
    while len(out) < len(ct):
        out += hashlib.sha256(DOM_STREAM + key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    flag = bytes(a ^ b for a, b in zip(ct, out))
    print(flag.decode(errors="replace"))

if __name__ == "__main__":
    main()
```

## Test

Testé **hors-ligne** contre le vrai `kem.py` : un oracle local appelant `kem.decaps`
avec un secret connu permet de reconstruire `s` à l'identique en ~1100 requêtes, puis
d'ouvrir une `box` scellée (flag de test retrouvé). Exécuté ensuite contre le service
live (~70 s) :

```
HTL{the_fo_check_leaks_every_coefficient}
```
