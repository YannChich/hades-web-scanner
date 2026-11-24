# Journal de bord — Hades

> Un résumé en français simple de ce qui est ajouté à Hades chaque jour.
> Objectif : que Yann comprenne l'évolution de l'outil sans avoir à lire le code.
> Entrée la plus récente en haut.

## 2026-11-24

**Ce que j'ai ajouté aujourd'hui**

- Un statut « vérifié » (`✓ verified`) sur les failles. Jusqu'ici, Hades disait seulement à quel
  point il était *confiant* qu'une faille existe. Maintenant, quand il a une *preuve concrète* (il a
  envoyé une attaque et le serveur a réagi exactement comme prévu), il la marque clairement comme
  prouvée, avec une petite phrase qui explique comment.
- Ce marqueur apparaît partout : une coche verte dans le terminal, un badge dans le rapport HTML, et
  deux champs (`verified` et `verification`) dans le rapport JSON pour les outils automatiques.
- J'ai branché ce statut sur tous les modules d'attaque « active » : injection SQL, XSS, injection de
  commandes, SSTI (templates), lecture de fichiers (LFI), redirection ouverte, et SSRF. Chacun écrit
  sa propre preuve (par ex. « le serveur a attendu le temps exact de la commande sleep injectée »).
- J'ai écrit 10 nouveaux tests automatiques pour garantir que ce comportement reste correct dans le
  temps, et j'ai mis à jour le README et la feuille de route.

**Les mots nouveaux**

- **Faille vérifiée** : une faille dont Hades a la preuve directe, par opposition à une faille
  seulement « soupçonnée » à partir d'indices. Un pentester peut donc traiter en priorité ce qui est
  certain.
- **XSS** : une faille qui permet d'injecter du code (JavaScript) dans une page, exécuté chez la victime.
- **SSTI** (Server-Side Template Injection) : le serveur « calcule » du texte fourni par l'utilisateur
  comme s'il s'agissait de code de template — ça mène souvent à l'exécution de commandes.
- **SSRF** (Server-Side Request Forgery) : on force le serveur à aller chercher une URL à notre place,
  ce qui permet d'atteindre des services internes normalement inaccessibles.

**Pourquoi ça compte**

Dans un rapport, séparer ce qui est *prouvé* de ce qui est *probable* fait gagner un temps énorme :
le pentester sait tout de suite quelles failles sont du solide à montrer au client, sans devoir
re-tester à la main. C'est un marqueur de sérieux qu'on retrouve dans les outils professionnels.

**La suite**

Un « registre de couverture » (coverage ledger) : savoir exactement quels modules ont tourné,
lesquels ont été ignorés ou ont échoué, et quelles pages/paramètres ont réellement été testés.
