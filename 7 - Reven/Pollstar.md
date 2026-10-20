# Pollstar — writeup

## Énoncé HTL

- **Titre :** Pollstar
- **Catégorie :** reven
- **Points :** 481
- **Solves :** 77
- **Connexion :** *aucune* (crackme local, pas de service réseau)

> *Everyone wants to be scheduled first.*
>
> `pollstar` est un petit crackme Linux x86-64 compilé depuis Rust et *strippé*.
> On lui donne une chaîne candidate, il répond `Correct.` ou `Nope.`. Exactement
> une entrée donne `Correct.` : c'est le flag.

Fichier fourni : `pollstar` (ELF x86-64, Rust, strippé). Le flag fait
**37 caractères**.

## Protections / modèle

Binaire Rust strippé, pas d'anti-debug. La chaîne de panique
*« user-provided comparison function does not correctly implement a total
order »* trahit l'usage d'un **tas / file de priorité** (`BinaryHeap`-like) : le
thème « scheduled first » est littéral, un *scheduler* choisit l'ordre de
traitement des caractères.

Le flux :

1. Lecture de 37 octets sur stdin (ou `argv[1]`).
2. Génération d'une **S-box** de 256 octets : permutation Fisher-Yates
   initialisée par un PCG de graine `0x1bd11bdaa9fc1a22`
   (mult. `0x5851f42d4c957f2d`, incr. `0x14057b7ef767814f`).
3. 37 « items » sont créés, un par caractère du flag. Chaque item est un
   **itérateur** (machine à états) qui, poussé 5 fois, transforme son octet.
4. Un **scheduler** traite les 37 items dans un ordre **dépendant du flag** :
   à chaque étape il choisit l'index restant qui minimise une priorité
   `splitmix(index, H)` où `H` est un état de hachage. Après avoir traité un
   item, `H` est mis à jour avec l'octet de flag de cet item.
5. Chaque item produit un octet écrit dans `out[index_d_origine]`.
6. `out` (37 octets) est comparé (`bcmp`) à une constante. Égalité → `Correct.`.

## La vulnérabilité

Toute la mécanique est **déterministe et inversible**, et surtout
**résoluble pas à pas** : l'ordre d'ordonnancement ne dépend que de `H`, et `H`
ne dépend que des octets déjà ordonnancés. On peut donc, étape par étape :

1. calculer quel index est ordonnancé (celui qui minimise `(priority(idx,H),idx)`) ;
2. **inverser** `out[idx]` (connu, c'est la cible) pour retrouver `flag[idx]` ;
3. mettre à jour `H` avec ce `flag[idx]` tout juste retrouvé.

### La transformation d'un octet (fonction `FUN_0010ee80`, l'itérateur)

Pour l'item d'index `idx`, ordonnancé à l'étape `t` : `cur = flag[idx]`, puis
**5 rounds** `i = 0..4`, avec un compteur global de rounds `R = 5*t + i` et
l'état `H` (constant pendant les 5 rounds de l'item) :

```python
def step_fwd(cur, i, R, H):
    b7   = (i*3 + R*5) & 0x3f
    b8   = (i*5 + R*7) & 0xff
    b6   = (R + i) & 7
    shift= (i + R*8) & 0x38
    idx2 = (i*17 + (H & 0xffffffff) + R*0x1f) & 0xff
    term = ((rotl64(H, b7) ^ H) >> shift) & 0xff
    return (b8 + (rotl8(S[cur], b6) ^ b8 ^ term ^ S[idx2]) + 0x3f) & 0xff
```

Comme `S` est une bijection et `rotl8` aussi, chaque round est inversible :

```python
def step_inv(cur, i, R, H):
    # mêmes b7,b8,b6,shift,idx2,term que ci-dessus
    X = (cur - b8 - 0x3f) & 0xff
    inner = X ^ b8 ^ term ^ S[idx2]
    return Sinv[rotr8(inner, b6)]
```

### Le scheduler (priorité + mise à jour de H)

```python
def priority(idx, H):                      # finaliseur type MurmurHash3/splitmix
    u = ((idx * 0x9E3779B97F4A7C15) & M) ^ H
    u = ((u ^ (u >> 33)) * 0xFF51AFD7ED558CCD) & M
    u = ((u ^ (u >> 33)) * 0xC4CEB9FE1A85EC53) & M
    return u ^ (u >> 33)

def Hupdate(H, b):                          # splitmix64 alimenté par l'octet
    u = (b + 0x9e3779b97f4a7c15 + H) & M
    u = (rotl64(u, 17) * 0x2545f4914f6cdd1d) & M
    return (u >> 0x1d ^ u) & M
```

## Résolution pas à pas

On génère d'abord la S-box exactement comme le binaire (Fisher-Yates du haut
vers le bas, indices 255→2) :

```python
M = (1 << 64) - 1
def sbox():
    S = list(range(256)); st = 0x1bd11bdaa9fc1a22; j = 0x101
    while True:
        st = (st*0x5851f42d4c957f2d + 0x14057b7ef767814f) & M
        jm1 = j - 1; r = st >> 0x21
        if jm1 <= r: r = r % (jm1 & 0xffffffff)
        S[j-2], S[r] = S[r], S[j-2]
        j = jm1
        if not (2 < jm1): break
    return S
```

Puis on déroule le scheduler à l'envers, en inversant chaque octet dès qu'il est
ordonnancé (`H` démarre à `0x243f6a8885a308d3`, la constante π de Blowfish) :

```python
H = 0x243f6a8885a308d3; R = 0
remaining = list(range(37)); flag = [0]*37
for t in range(37):
    sel = min(remaining, key=lambda ix: (priority(ix, H), ix))   # ordonnancé
    cur = target[sel]
    for i in range(4, -1, -1):                                   # 5 rounds inverses
        cur = step_inv(cur, i, R+i, H)
    flag[sel] = cur
    R += 5
    H = Hupdate(H, flag[sel])                                    # H avance
    remaining.remove(sel)
print(bytes(flag).decode())
```

## Script complet -> Script intégral

Script autonome : la S-box et la cible sont intégrées, aucune dépendance,
aucun binaire requis. Il affiche le flag :

```python
#!/usr/bin/env python3
# Pollstar (HTL 2026) - inverse le "scheduler" Rust pour recuperer le flag.
# Usage : python3 solve.py     (tout est integre)

M = (1 << 64) - 1

# octets cibles compares par bcmp (DAT_0010608c, 0x25 = 37 octets)
target = [18,195,26,103,130,224,49,37,179,116,182,136,48,60,177,88,97,220,215,
          131,241,140,141,144,133,155,159,208,99,86,50,97,223,186,113,86,110]

def rotl8(v, a): a &= 7; return ((v << a) | (v >> (8-a))) & 0xff
def rotr8(v, a): a &= 7; return ((v >> a) | (v << (8-a))) & 0xff
def rotl64(v, a): a &= 63; return ((v << a) | (v >> (64-a))) & M

def sbox():
    # permutation Fisher-Yates 256 octets, PCG graine 0x1bd11bdaa9fc1a22
    S = list(range(256)); st = 0x1bd11bdaa9fc1a22; j = 0x101
    while True:
        st = (st*0x5851f42d4c957f2d + 0x14057b7ef767814f) & M
        jm1 = j - 1; r = st >> 0x21
        if jm1 <= r:
            r = r % (jm1 & 0xffffffff)
        S[j-2], S[r] = S[r], S[j-2]
        j = jm1
        if not (2 < jm1):
            break
    return S

S = sbox()
Sinv = [0]*256
for i, v in enumerate(S):
    Sinv[v] = i

def priority(idx, H):
    u = ((idx * 0x9E3779B97F4A7C15) & M) ^ H
    u = ((u ^ (u >> 33)) * 0xFF51AFD7ED558CCD) & M
    u = ((u ^ (u >> 33)) * 0xC4CEB9FE1A85EC53) & M
    return u ^ (u >> 33)

def Hupdate(H, b):
    u = (b + 0x9e3779b97f4a7c15 + H) & M
    u = (rotl64(u, 17) * 0x2545f4914f6cdd1d) & M
    return (u >> 0x1d ^ u) & M

def step_inv(cur, i, R, H):
    b7   = (i*3 + R*5) & 0x3f
    b8   = (i*5 + R*7) & 0xff
    b6   = (R + i) & 7
    shift = (i + R*8) & 0x38
    idx2 = (i*17 + (H & 0xffffffff) + R*0x1f) & 0xff
    term = ((rotl64(H, b7) ^ H) >> shift) & 0xff
    X = (cur - b8 - 0x3f) & 0xff
    inner = X ^ b8 ^ term ^ S[idx2]
    return Sinv[rotr8(inner, b6)]

H = 0x243f6a8885a308d3      # etat de hachage initial (pi de Blowfish)
R = 0                       # compteur global de rounds (5 par item)
remaining = list(range(37))
flag = [0]*37
for t in range(37):
    # le scheduler choisit l'index restant de priorite minimale
    sel = min(remaining, key=lambda ix: (priority(ix, H), ix))
    cur = target[sel]
    for i in range(4, -1, -1):      # 5 rounds, inverses
        cur = step_inv(cur, i, R+i, H)
    flag[sel] = cur
    R += 5
    H = Hupdate(H, flag[sel])       # H avance avec l'octet retrouve
    remaining.remove(sel)

print(bytes(flag).decode())
```

Exécution :

```
$ python3 solve.py
HTL{the_executor_polls_in_your_order}
```

Vérification sur le binaire fourni :

```
$ printf 'HTL{the_executor_polls_in_your_order}' | ./pollstar
Correct.
```

## Flag

```
HTL{the_executor_polls_in_your_order}
```
