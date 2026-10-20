# Byte Ladder

- **Catégorie :** crypto — 584 points
- **CTF :** Hack Ton Lycée (HTL 2026, plateforme Yogosha)
- **Service :** `http://crypto.ctf.yogosha.com:9005`
- **Flag :** `HTL{ecb_leaks_one_byte_at_a_time}`

## Énoncé

> L'oracle ajoute un secret fixe à ce que vous envoyez et chiffre le tout en AES-ECB
> sous une clé par-processus. `POST /enc` avec un champ `data` (interprété comme hex
> si ça ressemble à de l'hex, sinon comme du texte brut). La réponse est
> `{"ct": "<hex>"}`, soit `AES-ECB(data || secret)`. Le secret contient le flag.

## Protections / modèle

- AES-256 en mode **ECB** (`modes.ECB()` dans `app.py`), clé aléatoire `os.urandom(32)`.
- La clé est **stable** pendant toute la durée de vie du processus (`gunicorn --workers 1`
  dans le `Dockerfile`), donc deux requêtes identiques donnent le même chiffré.
- Padding PKCS#7, bloc de 16 octets.
- Le secret (`/srv/flag.txt`) est concaténé **après** notre entrée : `encrypt(data + SECRET)`.

## La vulnérabilité

C'est le « byte-at-a-time ECB decryption » d'école. Le mode ECB chiffre chaque bloc de
16 octets **indépendamment** : deux blocs en clair identiques donnent deux blocs chiffrés
identiques.

Dans `app.py` :

```python
def encrypt(data):
    cipher = Cipher(algorithms.AES(KEY), modes.ECB())   # ECB : chaque bloc indépendant
    enc = cipher.encryptor()
    return enc.update(pkcs7(data)) + enc.finalize()

@app.post("/enc")
def enc():
    ...
    ct = encrypt(data + SECRET)                          # on contrôle `data`, pas `SECRET`
    return jsonify({"ct": ct.hex()})
```

Comme on contrôle la longueur de `data`, on peut **aligner** le secret sur les frontières
de bloc et faire fuiter un octet à la fois.

Remarque pratique : `parse_input` tente d'abord `bytes.fromhex(raw)`. On envoie donc
toujours notre préfixe **en hexadécimal** pour qu'il soit pris tel quel.

## Résolution pas à pas

Bloc de 16 octets. On note `oracle(x)` = `AES-ECB(x || secret)`.

**1. Trouver la longueur du secret.** On augmente le préfixe jusqu'à ce que le chiffré
gagne un bloc entier (c'est le padding qui bascule) :

```python
base_len = len(oracle(b""))
i = 1
while len(oracle(b"A" * i)) == base_len:   # on grossit le préfixe octet par octet
    i += 1
secret_len = base_len - i                  # taille réelle du secret
```

**2. Positionner l'octet inconnu en fin de bloc.** Si on a déjà `known` octets, on envoie
un bourrage `A...A` pour que le prochain octet inconnu tombe juste à la fin d'un bloc :

```python
pad  = b"A" * ((-len(known) - 1) % 16)     # pousse l'octet cible sur une frontière
bidx = (len(pad) + len(known)) // 16        # index du bloc qui finit par l'octet cible
sl   = slice(bidx * 16, (bidx + 1) * 16)    # le bloc à comparer
target = oracle(pad)[sl]                     # chiffré « de référence »
```

**3. Deviner l'octet par dictionnaire.** On teste les 256 valeurs possibles : celle dont le
bloc chiffré coïncide avec `target` est le bon octet.

```python
for b in range(256):
    if oracle(pad + known + bytes([b]))[sl] == target:
        known += bytes([b])
        break
```

**4. Répéter** jusqu'à avoir récupéré tout le secret.

## Script complet -> Script intégral

Autonome (bibliothèque standard uniquement), lançable par
`python3 solve.py crypto.ctf.yogosha.com 9005`.

```python
#!/usr/bin/env python3
"""Byte Ladder - AES-ECB byte-at-a-time secret recovery.
Usage: python3 solve.py <host> <port>   (defaults: crypto.ctf.yogosha.com 9005)
"""
import sys, json, urllib.request, urllib.parse

BLOCK = 16

def make_oracle(base):
    def oracle(data: bytes) -> bytes:
        # the server reads `data` as hex when it looks like hex, so always send hex
        body = urllib.parse.urlencode({"data": data.hex()}).encode()
        req = urllib.request.Request(base + "/enc", data=body)
        ct = json.load(urllib.request.urlopen(req))["ct"]
        return bytes.fromhex(ct)
    return oracle

def recover(oracle):
    base_len = len(oracle(b""))
    # find secret length: grow the prefix until the ciphertext gains a block
    i = 1
    while len(oracle(b"A" * i)) == base_len:
        i += 1
    secret_len = base_len - i
    known = b""
    while len(known) < secret_len:
        pad = b"A" * ((-len(known) - 1) % BLOCK)      # push next unknown byte to a block edge
        bidx = (len(pad) + len(known)) // BLOCK
        sl = slice(bidx * BLOCK, (bidx + 1) * BLOCK)
        target = oracle(pad)[sl]
        for b in range(256):
            if oracle(pad + known + bytes([b]))[sl] == target:
                known += bytes([b]); break
        else:
            break                                      # hit padding -> done
    return known

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "crypto.ctf.yogosha.com"
    port = sys.argv[2] if len(sys.argv) > 2 else "9005"
    base = f"http://{host}:{port}"
    secret = recover(make_oracle(base))
    print(secret.decode(errors="replace"))

if __name__ == "__main__":
    main()
```

## Test

Testé en local contre une réplique de l'oracle (même clé AES-256-ECB + secret connu) :
le secret est reconstruit à l'identique. Puis exécuté contre le service live, qui renvoie :

```
HTL{ecb_leaks_one_byte_at_a_time}
```
