# Crosswire

- **CTF :** Hack Ton Lycée (HTL) 2026
- **Catégorie :** infra
- **Points :** 584 — **Solves :** 69
- **Grader :** `http://infra.ctf.yogosha.com:7002`
- **Flag :** `HTL{pin_the_subject_not_just_the_audience}`

## Énoncé

La CI de `acme-corp/urlmin-deploy` déploie sur AWS sans aucune clé statique : le
workflow `deploy` demande un jeton OIDC GitHub Actions et l'échange, via le
fournisseur OIDC du compte, contre le rôle IAM `github-deploy-role`
(`sts:AssumeRoleWithWebIdentity`). Ce rôle peut écrire dans le bucket
d'artefacts de production.

Lors du dernier incident, un jeton OIDC capturé a montré qu'un run qui **n'était
pas** le déploiement de production assumait quand même `github-deploy-role`.
C'est la *trust policy* du rôle qui décide qui a le droit de faire cet échange,
et elle est actuellement trop permissive.

But : durcir la trust policy pour que le contexte capturé ne puisse plus assumer
le rôle, **sans** casser le vrai déploiement. Le grader évalue la policy soumise
en direct contre le vrai jeton de deploy ET le jeton d'incident ; il ne rend le
flag que si la policy est à la fois **secure** (incident rejeté) et
**functional** (le vrai deploy assume toujours le rôle et garde sa permission).

## Le modèle

- **Fichier à éditer :** `trust-policy.json` (le `AssumeRolePolicyDocument` du
  rôle).
- `deploy.yml` : le seul workflow censé atteindre le rôle (push sur `main`, lié
  à l'environnement protégé `production`).
- `captured-token.jwt` : le jeton OIDC observé pendant l'incident.

La trust policy fournie au départ :

```json
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:repository_owner": "acme-corp"
  }
}
```

Elle ne vérifie que **l'audience** (`aud`) et **le propriétaire du dépôt**
(`repository_owner`).

## La vulnérabilité

On décode le payload du jeton d'incident (`captured-token.jwt`, 2e segment en
base64url) :

```json
{
  "aud": "sts.amazonaws.com",
  "sub": "repo:acme-corp/urlmin-deploy:pull_request",
  "repository_owner": "acme-corp",
  "event_name": "pull_request",
  "ref": "refs/pull/42/merge",
  "job_workflow_ref": "acme-corp/urlmin-deploy/.github/workflows/ci.yml@refs/pull/42/merge"
}
```

Le jeton d'incident a `aud = sts.amazonaws.com` **et**
`repository_owner = acme-corp` : il satisfait donc les **deux** seules
conditions de la policy. N'importe quel workflow du moindre dépôt de
l'organisation `acme-corp` (y compris un `pull_request` déclenché par une PR
extérieure, workflow `ci.yml`, non lié à l'environnement `production`) peut
assumer le rôle de déploiement. C'est beaucoup trop large.

La granularité qui manque, c'est le claim **`sub`** (subject). Pour GitHub
Actions, `sub` encode précisément le contexte d'exécution :

- jeton d'incident : `sub = repo:acme-corp/urlmin-deploy:pull_request` ;
- vrai deploy : il est lié à `environment: production` dans `deploy.yml`
  (`environment: production`), donc GitHub émet
  `sub = repo:acme-corp/urlmin-deploy:environment:production`.

Il suffit donc d'**épingler le `sub`** sur le sujet exact du vrai déploiement.

## Résolution pas à pas

**1. Décoder le jeton capturé** pour lire son `sub` :

```python
import base64, json
jwt = open("extracted/captured-token.jwt").read().strip()
payload = jwt.split(".")[1]
payload += "=" * (-len(payload) % 4)                # padding base64url
print(json.loads(base64.urlsafe_b64decode(payload))["sub"])
# -> repo:acme-corp/urlmin-deploy:pull_request
```

**2. En déduire le `sub` du vrai deploy.** `deploy.yml` contient
`environment: production`, donc le sujet du jeton réel est :

```
repo:acme-corp/urlmin-deploy:environment:production
```

Les deux `sub` diffèrent : on peut discriminer dessus.

**3. Ajouter une condition `StringEquals` sur le `sub`** (on garde `aud`) :

```json
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": "repo:acme-corp/urlmin-deploy:environment:production"
  }
}
```

Le jeton d'incident (`...:pull_request`) ne correspond plus → **rejeté**.
Le vrai deploy (`...:environment:production`) correspond → **toujours OK**.

**4. Soumettre la policy au grader** et lire le verdict :

```python
import json, urllib.request
body = json.dumps({"trust_policy": policy}).encode()
req = urllib.request.Request(f"http://{host}:{port}/grade", data=body,
                             headers={"Content-Type": "application/json"})
print(json.loads(urllib.request.urlopen(req).read()))
# {"flag": "...", "functional": true, "passed": true, "secure": true}
```

> Remarque : on pinne le **sujet** (`sub`), pas seulement l'audience — d'où le
> flag. On pourrait aussi ajouter `repository`/`repository_id`, mais épingler le
> `sub` sur l'environnement `production` suffit et reste la pratique canonique.

## Script complet → Script intégral

Script autonome (stdlib seule, pas de dépendance exotique). Il construit la
trust policy durcie et la soumet au grader.

```python
#!/usr/bin/env python3
# Crosswire (HTL 2026 - infra) - solveur autonome.
# Usage : python3 solve.py <host> <port>
#   ex. : python3 solve.py infra.ctf.yogosha.com 7002
import sys, json, urllib.request

# --- Trust policy durcie ---------------------------------------------------
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    # LA correction : on fige le sujet exact du deploiement reel.
                    # Jeton d'incident : sub=repo:acme-corp/urlmin-deploy:pull_request -> rejete.
                    # Vrai deploy (lie a environment: production) :
                    #   sub=repo:acme-corp/urlmin-deploy:environment:production -> accepte.
                    "token.actions.githubusercontent.com:sub": "repo:acme-corp/urlmin-deploy:environment:production"
                }
            }
        }
    ]
}


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: python3 {sys.argv[0]} <host> <port>")
    host, port = sys.argv[1], sys.argv[2]
    url = f"http://{host}:{port}/grade"

    body = json.dumps({"trust_policy": TRUST_POLICY}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        resp = json.loads(r.read())

    print(json.dumps(resp, indent=2))
    if resp.get("flag"):
        print("\nFLAG:", resp["flag"])


if __name__ == "__main__":
    main()
```

Exécution :

```
$ python3 solve.py infra.ctf.yogosha.com 7002
{
  "flag": "HTL{pin_the_subject_not_just_the_audience}",
  "functional": true,
  "passed": true,
  "secure": true
}

FLAG: HTL{pin_the_subject_not_just_the_audience}
```

## Flag

```
HTL{pin_the_subject_not_just_the_audience}
```

> Testé : oui — soumis au grader live `infra.ctf.yogosha.com:7002`,
> `secure: true` et `functional: true`.
