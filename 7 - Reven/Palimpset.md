# Palimpsest — writeup

## Énoncé HTL

- **Titre :** Palimpsest
- **Catégorie :** reven
- **Connexion :** *aucune* (crackme local, pas de service réseau)

> *Someone scraped the parchment and wrote over it. Scrape again.*
>
> `palimpsest` est un petit crackme Linux x86-64. On lui donne une chaîne, il
> répond `Correct.` ou `Nope.`. Exactement une entrée donne `Correct.` : c'est
> le flag. Pas de service réseau, pas de fichier de flag : le flag est
> l'entrée acceptée, à extraire du binaire.

Fichier fourni : `palimpsest` (ELF x86-64). Le flag fait **32 caractères**.

## Protections / modèle

- **Anti-debug** : `ptrace(PTRACE_TRACEME)` (si déjà tracé → échec → le check
  est sauté) et lecture de `/proc/self/status` → `TracerPid`. Pour instrumenter,
  on patche les deux branches (`je`/`jne` à `0x116e` et `0x11a2`) en `nop`.
- Tout tient dans une seule fonction (entrée `.text` `0x1010c0`).

## La vulnérabilité

Le check est une **VM imbriquée**. La fonction :

1. Génère une suite PCG (LCG `mult=0x5851f42d4c957f2d`, `incr=0x14057b7ef767814f`)
   pour dériver un keystream, puis **XORe** un petit programme-octets de 34 octets
   de `.rodata` (`0x102038`) avec ce keystream (thème « palimpseste » :
   couche réécrite). Chaque instruction est déchiffrée à l'exécution puis
   re-chiffrée, donc statiquement : `prog[i] = rom[i] XOR keystream[i]`.
2. Interprète ce bytecode (registres `r[8]`, 3 régions mémoire : `region0` =
   sortie d'une transformation, `region1` = 32 octets constants, `region2` =
   entrée). Le programme décodé :
   - exige une longueur d'entrée de 32 ;
   - applique une transformation **`op0xb`** à l'entrée → `region0` ;
   - boucle `i=0..31` : `r1 |= (region0[i] XOR region1[i])` ;
   - accepte si `r1 == 0`.

   Donc **accepté ⇔ `op0xb(entrée) == C`** où `C` (region1) est connu :

   ```
   C = ec8354c422d8f6aa b41cc8490d90a53e a6d10bb66195ce40 67c7ed62e93f4bcb  (little-endian)
   ```

3. **`op0xb` est une seconde VM** (un interpréteur ARX). Les 32 octets d'entrée
   sont vus comme 8 mots de 32 bits (little-endian). Un petit programme
   d'opcodes `0xa1 / 0xb2 / 0xc3` (construit en mémoire à l'exécution) décrit
   **20 rounds** suivis d'un `0xa1` final :
   - **`0xa1 r`** : `buf[i] += CONST[r][i]` (addition 32 bits), `CONST` dérivé
     d'un autre LCG (graine `0x9e3779b97f4a7c15`) ;
   - **`0xb2 d s rot`** : mélange ARX sur deux mots
     `buf[d] = buf[d] + buf[s]` ; `buf[s] = rotl32(buf[s], rot) XOR buf[d]` ;
     appliqué aux paires `(0,1),(2,3),(4,5),(6,7)` avec les rotations
     `rotbl[r&7]` ;
   - **`0xc3`** : permutation des 8 mots `P = [2,5,0,7,4,1,6,3]`.

`op0xb` est donc une **permutation ARX bijective**, entièrement **inversible** :
on inverse chaque opération dans l'ordre inverse. Le flag est
`op0xb⁻¹(C)`.

### Inverse de chaque opération

- `0xa1` : `buf[i] -= CONST[r][i]`.
- `0xb2` : `buf[s] = rotr32(buf[s] XOR buf[d], rot)` ; `buf[d] -= buf[s]`.
- `0xc3` : permutation inverse de `P`.

## Résolution pas à pas

Tables (le round `r` indexe `rotbl[r & 7]`) :

```python
rotbl = [[13,17,21,25],[7,11,19,23],[5,9,15,27],[3,14,20,28],
         [6,10,18,24],[8,12,16,22],[4,13,26,30],[2,15,19,29]]
P = [2,5,0,7,4,1,6,3]
```

Constantes ARX via LCG (21*8 = 168 mots de 32 bits, le haut de l'état) :

```python
M = (1<<64)-1
st = 0x9e3779b97f4a7c15
CONST = []
for _ in range(168):
    st = (st*0x5851f42d4c957f2d + 0x14057b7ef767814f) & M
    CONST.append((st >> 32) & 0xffffffff)
```

Programme : 20 rounds `a1 + 4×b2 + c3`, puis un `a1` final (round 20) :

```python
ops = []
for r in range(20):
    ops.append(('a1', r))
    for (d, s), k in zip([(0,1),(2,3),(4,5),(6,7)], range(4)):
        ops.append(('b2', d, s, rotbl[r & 7][k]))
    ops.append(('c3',))
ops.append(('a1', 20))
```

Inversion de `C` → flag (les mots sont little-endian) :

```python
import struct
buf = list(struct.unpack('<8I', C))
for op in reversed(ops):
    ...  # inverse de a1 / b2 / c3
flag = struct.pack('<8I', *buf)
```

## Script complet -> Script intégral

Script autonome, sans dépendance, qui calcule le flag hors-ligne (aucun binaire
requis) :

```python
#!/usr/bin/env python3
# Palimpsest (HTL 2026) - inverse la VM ARX "op0xb" pour obtenir op0xb^-1(C).
# Usage : python3 solve.py      (tout est integre)
import struct

M   = (1 << 64) - 1
M32 = 0xffffffff
MUL = 0x5851f42d4c957f2d
INC = 0x14057b7ef767814f

# constante cible C = region1 comparee a op0xb(entree) (little-endian)
C = struct.pack('<4Q', 0xec8354c422d8f6aa, 0xb41cc8490d90a53e,
                       0xa6d10bb66195ce40, 0x67c7ed62e93f4bcb)

# table de constantes ARV : LCG, 168 mots (= 21 rounds * 8 mots), octet haut
st = 0x9e3779b97f4a7c15            # (-0x61c8864680b583eb) mod 2^64
CONST = []
for _ in range(168):
    st = (st * MUL + INC) & M
    CONST.append((st >> 32) & M32)

rotbl = [[13,17,21,25],[7,11,19,23],[5,9,15,27],[3,14,20,28],
         [6,10,18,24],[8,12,16,22],[4,13,26,30],[2,15,19,29]]
P    = [2,5,0,7,4,1,6,3]
Pinv = [P.index(i) for i in range(8)]

def rol32(v, r): r &= 31; return ((v << r) | (v >> (32-r))) & M32
def ror32(v, r): r &= 31; return ((v >> r) | (v << (32-r))) & M32

# sequence exacte des operations : 20 rounds (a1 + 4 melanges + permutation),
# puis un a1 final (round 20)
ops = []
for r in range(20):
    ops.append(('a1', r))
    for (d, s), k in zip([(0,1),(2,3),(4,5),(6,7)], range(4)):
        ops.append(('b2', d, s, rotbl[r & 7][k]))
    ops.append(('c3',))
ops.append(('a1', 20))

def op0xb(data):                      # transformation directe (pour verifier)
    buf = list(struct.unpack('<8I', data))
    for op in ops:
        if op[0] == 'a1':
            r = op[1]
            for i in range(8): buf[i] = (buf[i] + CONST[r*8 + i]) & M32
        elif op[0] == 'b2':
            _, d, s, rot = op
            nd = (buf[d] + buf[s]) & M32
            ns = rol32(buf[s], rot) ^ nd
            buf[d] = nd; buf[s] = ns
        else:
            buf = [buf[P[i]] for i in range(8)]
    return struct.pack('<8I', *buf)

def op0xb_inv(data):                   # transformation inverse
    buf = list(struct.unpack('<8I', data))
    for op in reversed(ops):
        if op[0] == 'a1':
            r = op[1]
            for i in range(8): buf[i] = (buf[i] - CONST[r*8 + i]) & M32
        elif op[0] == 'b2':
            _, d, s, rot = op
            olds = ror32(buf[s] ^ buf[d], rot)
            oldd = (buf[d] - olds) & M32
            buf[d] = oldd; buf[s] = olds
        else:
            buf = [buf[Pinv[i]] for i in range(8)]
    return struct.pack('<8I', *buf)

flag = op0xb_inv(C)
assert op0xb(flag) == C              # verification interne
print(flag.decode())
```

Exécution :

```
$ python3 solve.py
HTL{nested_vms_all_the_way_down}
```

Vérification sur le binaire fourni :

```
$ ./palimpsest 'HTL{nested_vms_all_the_way_down}'
Correct.
```

## Flag

```
HTL{nested_vms_all_the_way_down}
```
