# Latticework — writeup

## Énoncé HTL

- **Titre :** Latticework
- **Catégorie :** reven
- **Points :** 481
- **Solves :** 77
- **Connexion :** `nc reven.ctf.yogosha.com 31001`

> *No CPU, no `.text`, just fabric.* `latticework.bin` est un bitstream Lattice
> iCE40 d'un validateur de flag **bit-série** : il fait entrer un candidat bit
> par bit et lève un unique fil `valid` pour exactement un flux d'entrée. Ce flux
> est le flag.

Fichiers fournis : `latticework.bin` (bitstream iCE40 HX8K), `oracle`
(émulateur gate-level ELF x86-64 qui expose `clk/rst/din/valid` en TCP).

## Protections / modèle

Pas de protection : c'est un circuit. L'`oracle` est en réalité une simulation
**CXXRTL** (backend Yosys, symboles `cxxrtl_design::p_top`) de la netlist. Plutôt
que de dépaqueter le bitstream (iceunpack/yosys), on **reverse directement
l'émulateur** : toute la logique séquentielle du design est dans une seule
fonction `eval` (`FUN_001024b0`), très courte.

Protocole TCP (une ligne par commande) : `reset`, `in <0|1>`, `step [n]`,
`valid`, `quit`.

## La vulnérabilité

La fonction `eval` décrit un automate minuscule. Son état :

- **`pos`** : compteur de position de bit, 0..0x10f (272 bits).
- **`m5`** : compteur modulo 5 (il faut **5 coups d'horloge par bit**).
- **`lfsr`** : un LFSR de Galois 23 bits, graine `0x5e3a91`, qui **avance à
  chaque coup d'horloge**.
- **`acc`** : bit « collant » de non-correspondance (0 = tout correspond).
- **`valid`** : la sortie.
- une **BRAM** initialisée avec 17 mots de 16 bits (272 bits).

À chaque bit (quand `m5 == 0`), le design calcule le bit de BRAM à la position
`pos` et exige :

```
din XOR lfsr_bit  ==  bram_bit(pos)
```

Au dernier bit (`pos == 0x10f`), `valid` prend la valeur `acc == 0` (aucune
erreur). Autrement dit, le flux d'entrée accepté est **entièrement déterminé** :

```
din(k) = bram_bit(k) XOR lfsr_bit(au moment de l'échantillon du bit k)
```

Comme le LFSR avance 5 fois par bit, le bit de LFSR utilisé pour le bit `k` est
le bit 0 du LFSR après `5*k` avances depuis la graine. On déroule, on récupère
272 bits, on les range **LSB en premier** → 34 octets ASCII = le flag.

### Détails tirés de `FUN_001024b0`

BRAM (mots 16 bits, `bram_bit(pos) = (words[pos>>4] >> (pos&0xf)) & 1`) :

```
0x9179,0x92a7,0x0f96,0xf637,0x7316,0x0c5b,0xf888,0xca31,
0x6340,0xbf6c,0x3bca,0x02ca,0x8d44,0x82ba,0xda41,0x792a,0xecb9
```

LFSR de Galois 23 bits (graine `0x5e3a91`) :

```python
def lfsr_next(s):
    b0 = s & 1
    sh = s >> 1
    if b0 == 0:
        return sh & 0x3fffff
    return (sh & 0x1ffff) | ((sh & 0x20000) ^ 0x20000) | (sh & 0x3c0000) | 0x400000
```

## Résolution pas à pas

On génère la suite de bits du LFSR échantillonnés (un par bit, le LFSR avançant
5 fois entre deux échantillons) :

```python
s = 0x5e3a91
samp = []
for k in range(272):
    samp.append(s & 1)        # bit 0 du LFSR à l'instant de l'échantillon
    for _ in range(5):        # 5 coups d'horloge par bit
        s = lfsr_next(s)
```

On XORe avec les bits de la BRAM pour obtenir les bits d'entrée attendus :

```python
din = [bram_bit(k) ^ samp[k] for k in range(272)]
```

On range les bits LSB en premier pour reconstituer les octets :

```python
flag = bytearray(272 // 8)
for i, bit in enumerate(din):
    if bit:
        flag[i >> 3] |= 1 << (i & 7)
print(bytes(flag).decode())
```

## Script complet -> Script intégral

Script autonome. Sans argument il **calcule et affiche le flag** (hors-ligne).
Avec `python3 solve.py <host> <port>` il rejoue en plus le protocole sur
l'oracle (ou le service distant) pour confirmer `valid 1` — en pur socket, sans
dépendance.

```python
#!/usr/bin/env python3
# Latticework (HTL 2026) - reconstruit le flux bit-serie accepte par le design.
# Usage :
#   python3 solve.py                 # calcule et affiche le flag (hors-ligne)
#   python3 solve.py <host> <port>   # calcule, puis verifie sur l'oracle TCP
import sys, socket, time

# BRAM initialisee (17 mots de 16 bits) lue par le design -> 272 bits
WORDS = [0x9179,0x92a7,0x0f96,0xf637,0x7316,0x0c5b,0xf888,0xca31,
         0x6340,0xbf6c,0x3bca,0x02ca,0x8d44,0x82ba,0xda41,0x792a,0xecb9]
NBITS = 272

def bram_bit(pos):
    return (WORDS[pos >> 4] >> (pos & 0xf)) & 1

def lfsr_next(s):                       # LFSR de Galois 23 bits
    b0 = s & 1
    sh = s >> 1
    if b0 == 0:
        return sh & 0x3fffff
    return (sh & 0x1ffff) | ((sh & 0x20000) ^ 0x20000) | (sh & 0x3c0000) | 0x400000

def recover_bits():
    s = 0x5e3a91                        # graine du LFSR (reset du design)
    din = []
    for k in range(NBITS):
        lfsr_bit = s & 1                # bit echantillonne pour le bit k
        din.append(bram_bit(k) ^ lfsr_bit)
        for _ in range(5):              # 5 coups d'horloge par bit de flag
            s = lfsr_next(s)
    return din

def bits_to_flag(din):
    out = bytearray(NBITS // 8)
    for i, bit in enumerate(din):       # LSB en premier dans chaque octet
        if bit:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)

def verify_remote(host, port, din):
    s = socket.create_connection((host, int(port)), timeout=10)
    s.sendall(b"reset\n")
    for b in din:
        s.sendall(b"in %d\nstep 5\n" % b)   # 5 coups d'horloge par bit
    s.sendall(b"valid\nquit\n")
    time.sleep(1.0)
    s.settimeout(3.0)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    lines = [l for l in data.decode(errors="replace").split("\n") if l.strip()]
    return lines[-1] if lines else "(aucune reponse)"

def main():
    din = recover_bits()
    flag = bits_to_flag(din)
    print(flag.decode())
    if len(sys.argv) >= 3:
        print("oracle ->", verify_remote(sys.argv[1], sys.argv[2], din))

if __name__ == "__main__":
    main()
```

Exécution :

```
$ python3 solve.py
HTL{the_fabric_remembers_the_flag}
```

Vérification (simulation fidèle du circuit, ou oracle `nc` local/distant) :
`valid 1` pour ce flux, `valid 0` dès qu'un seul bit change.

## Flag

```
HTL{the_fabric_remembers_the_flag}
```
