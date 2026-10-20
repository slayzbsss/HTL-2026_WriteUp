# Seam Split

- **Catégorie :** crypto
- **CTF :** Hack Ton Lycée (HTL 2026, plateforme Yogosha)
- **Service :** `http://crypto.ctf.yogosha.com:9004`
- **Flag :** `HTL{interior_bits_factor_together}`

## Énoncé

> Une appliance a généré des clés RSA « au rabais » et a publié tous ses modules publics.
> Pour économiser l'entropie, le firmware a réutilisé un **même bloc de poids fort** dans
> chaque nombre premier privé, mais l'a placé à un **décalage de bits différent et non
> divulgué** pour chaque clé — la « couture » (seam) se cache donc à une position
> intérieure inconnue de chaque module. Un de ces modules chiffre le flag sous `e = 65537`.
> Le vérifieur ne détient aucune clé privée : récupérez un facteur non trivial du module
> cible et envoyez-le à `/factor`, qui termine le déchiffrement.

## Protections / modèle

- `keys.json` (aussi servi par `GET /keys.json`) contient :
  - `e = 65537` ;
  - `moduli` : 8 modules RSA `N_0 .. N_7` (1011–1028 bits), en hex ;
  - `flag_index = 2` : le module qui chiffre le flag ;
  - `flag_ciphertext = m^e mod N_2`.
- `POST /factor {"p": "<hex>"}` : le serveur vérifie que `p` est un diviseur **non trivial**
  de `N_{flag_index}`, puis calcule `q = N/p`, `d = e^{-1} mod φ(N)`, `m = c^d mod N` et
  renvoie le texte clair. Aucune clé privée stockée → **la seule voie est de factoriser N_2**.

## La vulnérabilité

Les primes partagent un bloc de bits commun (la « couture »), mais à une position
intérieure inconnue et différente par clé. En pratique (vérifié sur les clés réelles),
les primes sont **déséquilibrés** : `N_2 = p·q` avec `p` d'environ **400 bits** et `q`
d'environ **615 bits**, et c'est le facteur de ~400 bits qui est partagé entre toutes les
clés.

C'est le cadre de la **factorisation implicite** (famille May–Ritzenhofen / *Generalized
Implicit Factorization Problem*, Feng–Nitaj–Pan, arXiv 2304.08718) : quand plusieurs
modules RSA partagent un grand bloc de bits dans un de leurs facteurs, un réseau
(lattice) + réduction LLL révèle ces facteurs.

Idée clé : si on **aligne** les modules pour que le bloc partagé coïncide (décalage à
gauche de chacun pour qu'ils aient tous la même taille), alors il existe une combinaison
linéaire **à petits coefficients** des modules alignés qui annule la partie partagée. LLL
trouve cette combinaison, et les coefficients obtenus sont des multiples des facteurs
recherchés — un simple `pgcd` avec chaque module donne le facteur.

## Résolution pas à pas

**1. Récupérer les modules** via `GET /keys.json`.

```python
data = GET /keys.json
N   = [int(h,16) for h in data["moduli"]]     # 8 modules
idx = int(data["flag_index"])                 # 2
```

**2. Aligner la couture.** On décale chaque module à gauche pour qu'ils aient tous la
taille du plus grand : les blocs de poids fort partagés se superposent.

```python
maxbits = max(x.bit_length() for x in N)
Np = [N[i] << (maxbits - N[i].bit_length()) for i in range(len(N))]
```

**3. Construire le réseau.** Matrice `n × (2n-1)` : un poids `W = 2^550` sur la diagonale
(pour forcer de petits coefficients), et des colonnes de « couplage » qui encodent, pour
chaque `j`, la relation `a_0·N'_j − a_j·N'_0`.

```python
W = 1 << 550
B = IntegerMatrix(n, 2*n - 1)
B[0, 0] = W
for j in range(1, n):
    B[0, (n-1)+j] = Np[j]          # ligne 0 : N'_j
    B[j, j]       = W              # diagonale
    B[j, (n-1)+j] = -Np[0]         # ligne j : -N'_0
```

**4. Réduire avec LLL.** La première ligne réduite contient `a_i · W` dans ses `n`
premières coordonnées.

```python
LLL.reduction(B)
```

**5. Lire les facteurs.** Pour chaque `i`, `a_i = |row0[i]| / W`, et `pgcd(a_i, N_i)`
donne un facteur non trivial.

```python
for i in range(n):
    ai = abs(B[0, i]) // W
    g = gcd(ai, N[i])
    if 1 < g < N[i]:
        facts[i] = g               # facteur de N_i
```

**6. Soumettre le facteur de N_2** à `/factor` ; le serveur termine le déchiffrement RSA
et renvoie le flag.

```python
p = facts[idx]                     # facteur de N_2 (p*q == N_2 vérifié)
flag = POST /factor {"p": hex(p)}
```

## Script complet -> Script intégral

Dépendance : `fpylll` (réduction LLL). Installable via
`python3 -m venv venv && venv/bin/pip install fpylll cysignals`.
Lançable par `python3 solve.py crypto.ctf.yogosha.com 9004`.

```python
#!/usr/bin/env python3
"""Seam Split - implicit (GIFP-style) factorization of a batch of RSA moduli
that share a high-entropy block across their primes. Left-align the moduli so
the shared seam coincides, run LLL, read a factor of each N off the short vector.
Needs: fpylll.  Usage: python3 solve.py <host> <port>
"""
import sys, json, urllib.request, urllib.error
from math import gcd
from fpylll import IntegerMatrix, LLL

def jget(url): return json.load(urllib.request.urlopen(url))
def jpost(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    try: return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e: return json.load(e)

def factor_batch(N):
    n = len(N)
    maxbits = max(x.bit_length() for x in N)
    Np = [N[i] << (maxbits - N[i].bit_length()) for i in range(n)]  # align the seam
    W = 1 << 550
    B = IntegerMatrix(n, 2 * n - 1)
    B[0, 0] = W
    for j in range(1, n):
        B[0, (n - 1) + j] = Np[j]
        B[j, j] = W
        B[j, (n - 1) + j] = -Np[0]
    LLL.reduction(B)
    facts = {}
    for i in range(n):
        ai = abs(B[0, i]) // W
        if ai:
            g = gcd(ai, N[i])
            if 1 < g < N[i]:
                facts[i] = g
    return facts

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "crypto.ctf.yogosha.com"
    port = sys.argv[2] if len(sys.argv) > 2 else "9004"
    base = f"http://{host}:{port}"
    data = jget(base + "/keys.json")
    N = [int(h, 16) for h in data["moduli"]]
    idx = int(data["flag_index"])
    facts = factor_batch(N)
    p = facts[idx]
    assert N[idx] % p == 0
    out = jpost(base + "/factor", {"p": format(p, "x")})
    print(out.get("flag") or out)

if __name__ == "__main__":
    main()
```

## Test

Testé **hors-ligne** sur le `keys.json` fourni : le réseau + LLL factorise les 8 modules
en ~0,1 s ; pour `N_2`, on obtient `p` (400 bits) et `q = N_2/p` (615 bits) avec
`p·q == N_2`. Déchiffrement RSA local du `flag_ciphertext` → `HTL{...}`. Puis confirmé
contre le service live via `/factor` :

```
HTL{interior_bits_factor_together}
```
