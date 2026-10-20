# Sidewinder

- **CTF :** Hack Ton Lycée (HTL) 2026
- **Catégorie :** infra
- **Grader :** `http://infra.ctf.yogosha.com:7001`
- **Flag :** `HTL{a_dot_is_not_a_wildcard}`

## Énoncé

Une plateforme de paiement fait tourner son *ledger* derrière un service mesh.
Les workloads s'authentifient en mTLS et le sidecar du ledger applique une
`AuthorizationPolicy` censée n'admettre que **deux** appelants :

- le **checkout writer** — service account `checkout.v2` dans le namespace
  `pay` — autorisé à `POST /ledger/append` ;
- le **reconciler** — service account `reconciler` dans le namespace
  `ledger-ops` — autorisé à `GET /ledger/reconcile`.

Tout le reste doit être rejeté par le sidecar. Or un rapport red-team montre
qu'un **imposteur** atteint `POST /ledger/append` alors qu'il n'est pas
`checkout.v2`.

But : re-scoper la policy pour que tous les imposteurs reçoivent `403`, tout en
gardant `200` pour les **deux** appelants légitimes sur leur verbe/chemin
autorisé. Verrouiller un appelant légitime ne compte pas.

## Le modèle de matching

Point clé donné par l'énoncé :

> Ce build du mesh compile chaque entrée `principals`, `hosts`, `paths` et
> valeur d'en-tête en un **matcher RE2** et exige un **match plein-chaîne**
> (full-string). `*` devient `.*`. Les autres caractères sont utilisés
> **verbatim**.

L'identité est le SPIFFE URI SAN du certificat du workload, p. ex.
`spiffe://cluster.local/ns/pay/sa/checkout.v2`. Le sidecar retire le schéma
`spiffe://` et compare le reste à chaque entrée `principals`.

La policy fournie (handout) :

```yaml
principals:
  - "cluster.local/ns/pay/sa/checkout.v2"      # rule 1 (POST /ledger/append)
...
principals:
  - "cluster.local/ns/ledger-ops/sa/reconciler"  # rule 2 (GET /ledger/reconcile)
```

## La vulnérabilité

Dans une regex RE2, le caractère `.` **n'est pas un point littéral** : c'est un
métacaractère qui matche **n'importe quel caractère**. Comme l'entrée est
utilisée « verbatim » puis compilée en RE2 full-string, l'entrée :

```
cluster.local/ns/pay/sa/checkout.v2
```

se comporte comme la regex `cluster.local/ns/pay/sa/checkout.v2`, où chaque `.`
accepte un caractère quelconque. Résultat, le `.` de `checkout.v2` capte aussi
bien le vrai `checkout.v2` que tout imposteur de la forme `checkout?v2` :

- `cluster.local/ns/pay/sa/checkout-v2` (le `-` est capté par le `.`),
- `cluster.local/ns/pay/sa/checkoutXv2`, etc.

Un service account nommé `checkout-v2` dans le namespace `pay` (nom DNS-1123
tout à fait valide) présente donc une identité qui **matche** l'entrée
`principals` et obtient `POST /ledger/append`. C'est l'imposteur du rapport.

La correction : **échapper les points** pour qu'ils redeviennent littéraux
(`\.`), de sorte que seule l'identité exacte matche.

## Vérification locale du matcher

On reproduit la logique du mesh en Python (`re.fullmatch`, `*` → `.*`) :

```python
import re
def matches(pattern, identity):
    return re.compile(pattern.replace('*', '.*') + r'\Z').fullmatch(identity) is not None

legit = "cluster.local/ns/pay/sa/checkout.v2"
imp   = "cluster.local/ns/pay/sa/checkout-v2"

print(matches("cluster.local/ns/pay/sa/checkout.v2",   legit))  # True
print(matches("cluster.local/ns/pay/sa/checkout.v2",   imp))    # True  <- FUITE
print(matches(r"cluster\.local/ns/pay/sa/checkout\.v2", legit)) # True
print(matches(r"cluster\.local/ns/pay/sa/checkout\.v2", imp))   # False <- corrige
```

Avec les points échappés, l'imposteur `checkout-v2` ne matche plus, mais le
`checkout.v2` légitime matche toujours.

## Résolution pas à pas

**1. Récupérer la baseline** depuis le grader (modèle d'édition) :

```python
import urllib.request
policy = urllib.request.urlopen(f"http://{host}:{port}/policy").read().decode()
```

**2. Échapper tous les points** dans les deux entrées `principals` :

```yaml
# rule 1
- 'cluster\.local/ns/pay/sa/checkout\.v2'
# rule 2
- 'cluster\.local/ns/ledger-ops/sa/reconciler'
```

(On met des quotes simples YAML pour que `\.` passe tel quel, sans
interprétation d'échappement.)

**3. Ne rien casser d'autre** : on conserve à l'identique `hosts`, `methods`,
`paths` et la condition `when` sur l'en-tête `x-ledger-tier` (c'est une
contrainte légitime du checkout, pas le bug). On ne fait que resserrer les
identités.

**4. Soumettre** la policy au grader et lire le verdict :

```python
req = urllib.request.Request(f"http://{host}:{port}/grade",
                             data=policy.encode(),
                             headers={"Content-Type": "application/x-yaml"})
print(urllib.request.urlopen(req).read().decode())
# {"checks":[{"check":"authorized-callers-served","passed":true},
#            {"check":"impostor-identities-denied","passed":true}],
#  "flag":"...","passed":true}
```

> `/apply` et `/grade` acceptent tous deux la policy postée en brut. Un `GET
> /grade` sans corps ne soumet rien et ne rend jamais le flag.

## Script complet → Script intégral

Script autonome (stdlib seule, pas de dépendance exotique). Il embarque la
policy corrigée et la soumet au grader.

```python
#!/usr/bin/env python3
# Sidewinder (HTL 2026 - infra) - solveur autonome.
# Usage : python3 solve.py <host> <port>
#   ex. : python3 solve.py infra.ctf.yogosha.com 7001
import sys, urllib.request

# --- AuthorizationPolicy corrigee (points echappes) ------------------------
POLICY = r"""apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: ledger-allow
  namespace: ledger
spec:
  selector:
    matchLabels:
      app: ledger
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - 'cluster\.local/ns/pay/sa/checkout\.v2'
      to:
        - operation:
            hosts:
              - "Ledger.pay.svc.cluster.local"
            methods:
              - "POST"
            paths:
              - "/ledger/append"
      when:
        - key: request.headers[x-ledger-tier]
          values:
            - "internal"
            - "gold"
    - from:
        - source:
            principals:
              - 'cluster\.local/ns/ledger-ops/sa/reconciler'
      to:
        - operation:
            methods:
              - "GET"
            paths:
              - "/ledger/reconcile"
"""


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: python3 {sys.argv[0]} <host> <port>")
    host, port = sys.argv[1], sys.argv[2]
    # /grade et /apply acceptent tous deux la policy postee en brut.
    url = f"http://{host}:{port}/grade"

    req = urllib.request.Request(
        url, data=POLICY.encode(),
        headers={"Content-Type": "application/x-yaml"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        print(r.read().decode())


if __name__ == "__main__":
    main()
```

Exécution :

```
$ python3 solve.py infra.ctf.yogosha.com 7001
{"checks":[{"check":"authorized-callers-served","passed":true},{"check":"impostor-identities-denied","passed":true}],"flag":"HTL{a_dot_is_not_a_wildcard}","passed":true}
```

## Flag

```
HTL{a_dot_is_not_a_wildcard}
```

> Testé : oui — logique du matcher reproduite en local (`re.fullmatch`) **et**
> policy soumise au grader live `infra.ctf.yogosha.com:7001`
> (`authorized-callers-served` + `impostor-identities-denied` tous deux `true`).
>
> Note : la baseline servie par `GET /policy` du grader a parfois déjà les
> points échappés ; c'est bien le handout d'origine (`manifests/authz.yaml`),
> aux points **non** échappés, qui est vulnérable — on l'a vérifié, il échoue
> sur `impostor-identities-denied`.
