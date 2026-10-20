# Wavefront — writeup

## Énoncé HTL

- **Titre :** Wavefront
- **Catégorie :** reven
- **Connexion :** *aucune* (crackme local, pas de service réseau)

> *A shader that only agrees with itself.*
>
> `wavefront` est un crackme Vulkan compute « headless ». Il charge un kernel
> SPIR-V *strippé* et l'exécute sur un device Vulkan logiciel (Mesa lavapipe),
> pas de GPU requis. On lui donne une chaîne candidate, il répond `Correct.` ou
> `Nope.`. Exactement une entrée donne `Correct.` : c'est le flag.

Fichiers fournis : `wavefront` (hôte ELF x86-64), `wavefront.spv` (kernel),
`perm.bin`, `sigma.bin` (permutations, u32 count + valeurs),
`texture.bin` (texture 60 octets R8_UNORM).

## Protections / modèle

Aucune protection particulière. Le flag fait **30 caractères** (le kernel
s'exécute avec `LocalSize 30` → 30 *lanes*, une lane par caractère). Toute la
logique est dans le SPIR-V ; l'hôte se contente de charger les buffers et de
compter les désaccords.

On peut exécuter le binaire localement (ici testé sur un vrai GPU RADV, mais
lavapipe marche aussi) :

```
$ ./wavefront 'HTL{....}'
Nope.
```

## La vulnérabilité

Le kernel (`spirv-dis wavefront.spv`) est entièrement réversible. Mapping des
buffers :

- binding 0 = **flag** (candidat), binding 1 = **perm**, binding 2 = **sigma**,
  binding 3 = compteur de résultat (atomic add), binding 4 = **texture**.

Chaque lane `L` (0..29) :

1. **État initial** : `state[L] = flag[perm[L]] & 0xff`.
2. **16 rounds** de mélange inter-lanes. Dans chaque round `m` :
   - `A[L] = (state[L] + K(m,L)) & 0xff` où `K` est une petite fonction de
     hachage (`%15` dans le SPIR-V) qui ne dépend que de `(m, L)` — donc une
     constante.
   - `nb = A[L xor 1]` (échange papillon via `OpGroupNonUniformShuffleXor`).
   - **lane paire** : `u[L] = (A[L] + nb) & 0xff`.
   - **lane impaire** : `u[L] = rotl8(A[L], SHIFTS[m]) xor ((nb + A[L]) & 0xff)`.
   - **reshuffle** : `state[L] = u[sigma[L]]`.
3. **Comparaison finale** : `state[L]` doit valoir l'octet lu dans la texture.
   La texture (60 texels R8) est échantillonnée en `u = (2L+1)/60` avec un
   **filtrage linéaire** → la valeur attendue est la **moyenne** des deux texels
   voisins : `expected[L] = round((texture[2L] + texture[2L+1]) / 2)`.

Le nombre total de désaccords (somme sur les 30 lanes) doit être 0 pour obtenir
`Correct.`.

Comme chaque étape est inversible, il n'y a pas besoin de solveur : on part des
valeurs attendues et on **remonte les 16 rounds à l'envers**.

### Pourquoi c'est inversible

Pour une paire papillon `(e = 2k, o = 2k+1)` on a, en avant :

```
u[e] = A[e] + A[o]                      (mod 256)
u[o] = rotl8(A[o], sh) xor u[e]
```

donc à l'envers :

```
A[o] = rotr8(u[o] xor u[e], sh)
A[e] = (u[e] - A[o]) mod 256
```

Le reshuffle `sigma` et l'ajout de `K` s'inversent trivialement.

## Résolution pas à pas

Les constantes `K` et les décalages (tableau `%113` du SPIR-V) :

```python
SHIFTS = [3,5,2,7,4,6,1,3,5,2,7,4,6,1,3,5]      # tableau %113

def K(m, lane):                                  # fonction %15 du SPIR-V
    t = (m*73 + lane*41 + 17) & 0xffffffff
    t ^= t >> 3; t &= 0xffffffff
    t = (t*45 + 7) & 0xffffffff
    return (t ^ (t >> 5)) & 0xff
```

Rotations 8 bits (fonction `%11`) :

```python
def rotl8(v, a): a &= 7; return ((v << a) | (v >> (8-a))) & 0xff
def rotr8(v, a): a &= 7; return ((v >> a) | (v << (8-a))) & 0xff
```

Valeurs attendues = échantillonnage linéaire de la texture :

```python
expected = [round((texture[2*L] + texture[2*L+1]) / 2) for L in range(30)]
```

Inversion d'un round (de `state` après le round vers `state` avant) :

```python
def inv_round(state, m):
    u = [0]*30
    for L in range(30): u[sigma[L]] = state[L]          # inverse reshuffle
    A = [0]*30; sh = SHIFTS[m]
    for k in range(15):                                  # inverse papillon
        e, o = 2*k, 2*k+1
        A[o] = rotr8(u[o] ^ u[e], sh)
        A[e] = (u[e] - A[o]) & 0xff
    return [(A[L] - K(m, L)) & 0xff for L in range(30)]  # inverse +K
```

On remonte les 16 rounds puis on replace via `perm` :

```python
state = expected[:]
for m in range(15, -1, -1):
    state = inv_round(state, m)          # state == flag[perm[L]]
flag = [0]*30
for L in range(30): flag[perm[L]] = state[L]
print(bytes(flag).decode())
```

## Script complet -> Script intégral

Script autonome (données `perm`/`sigma`/`texture` intégrées, aucune dépendance,
aucun GPU requis). Il affiche directement le flag :

```python
#!/usr/bin/env python3
# Wavefront (HTL 2026) - recupere le flag en inversant le kernel SPIR-V.
# Usage : python3 solve.py        (les donnees sont integrees)

perm = [0,16,8,24,4,20,12,28,2,18,10,26,6,22,14,1,17,9,25,5,
        21,13,29,3,19,11,27,7,23,15]
sigma = [24,10,9,19,16,2,1,29,15,12,22,21,7,4,26,25,11,8,18,17,
         3,0,28,14,13,23,20,6,5,27]
texture = [175,183,174,182,129,137,161,169,113,121,31,39,225,233,24,32,
           188,196,150,158,30,38,22,30,131,139,0,4,207,215,116,124,
           176,184,173,181,70,78,138,146,165,173,82,90,45,53,34,42,
           191,199,52,60,60,68,0,0,230,238,218,226]

N = 30
SHIFTS = [3,5,2,7,4,6,1,3,5,2,7,4,6,1,3,5]

def K(m, lane):                       # fonction de hachage par (round, lane)
    t = (m*73 + lane*41 + 17) & 0xffffffff
    t ^= t >> 3; t &= 0xffffffff
    t = (t*45 + 7) & 0xffffffff
    return (t ^ (t >> 5)) & 0xff

def rotl8(v, a): a &= 7; return ((v << a) | (v >> (8-a))) & 0xff
def rotr8(v, a): a &= 7; return ((v >> a) | (v << (8-a))) & 0xff

# valeur attendue par lane = echantillonnage lineaire (moyenne de 2 texels)
expected = [round((texture[2*L] + texture[2*L+1]) / 2) for L in range(N)]

def inv_round(state, m):
    u = [0]*N
    for L in range(N):
        u[sigma[L]] = state[L]                 # inverse du reshuffle sigma
    A = [0]*N; sh = SHIFTS[m]
    for k in range(N//2):                      # inverse du papillon pair/impair
        e, o = 2*k, 2*k+1
        A[o] = rotr8(u[o] ^ u[e], sh)
        A[e] = (u[e] - A[o]) & 0xff
    return [(A[L] - K(m, L)) & 0xff for L in range(N)]   # inverse du +K(m,L)

state = expected[:]
for m in range(15, -1, -1):
    state = inv_round(state, m)                # => state[L] == flag[perm[L]]

flag = [0]*N
for L in range(N):
    flag[perm[L]] = state[L]
print(bytes(flag).decode())
```

Exécution :

```
$ python3 solve.py
HTL{four_thousand_lanes_agree}
```

Vérification sur le binaire fourni :

```
$ printf 'HTL{four_thousand_lanes_agree}' | ./wavefront
Correct.
```

## Flag

```
HTL{four_thousand_lanes_agree}
```
