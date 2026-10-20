# Accueil : Bienvenue sur Hack Ton Lycée : Writeup

- **Catégorie :** webex (découverte)
- **Connexion :** `https://htl.ctf.yogosha.com/`

## Énoncé

Page d'accueil du concours. Le flag est caché quelque part dans la page.

## Vulnérabilité

Les commentaires HTML (`<!-- ... -->`) ne sont pas affichés par le navigateur, mais le serveur les envoie quand même. Un secret placé dans un commentaire est donc visible par tout le monde.

## Résolution

1. Ouvrir `https://htl.ctf.yogosha.com/`.
2. Afficher le code source : `Ctrl + U` (Windows/Linux) ou `Cmd + Option + U` (macOS).
3. Chercher `HTL{` avec `Ctrl + F`.

Le commentaire suivant apparaît :

```html
<!-- Bravo, tu as trouvé le premier flag : HTL{bienvenue_sur_hack_ton_lycee} -->
```

## Flag

```
HTL{bienvenue_sur_hack_ton_lycee}
```

## Leçon

Un secret envoyé au navigateur, même dans un commentaire, est lisible par n'importe quel visiteur. Il doit rester côté serveur.
