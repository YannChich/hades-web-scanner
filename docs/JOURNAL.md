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
- Un « registre de couverture » (coverage ledger). À la fin d'un scan, Hades dit maintenant
  clairement ce qu'il a *réellement testé* : quels modules ont tourné, lesquels ont été sautés (par
  exemple en mode sûr), lesquels ont planté ou dépassé le temps imparti, et lesquels n'ont pas été
  lancés du tout. Il indique aussi la « surface » trouvée en explorant le site (nombre de pages,
  d'URL avec paramètres, de formulaires) et si un module d'attaque a bien testé cette surface.
- Ce registre s'affiche dans le terminal (section « Coverage ») et dans le rapport HTML, et il est
  aussi dans le rapport JSON pour les outils automatiques. 11 tests de plus pour le fiabiliser.
- Un « gouverneur de bruit ». Hades gère maintenant mieux son rythme d'envoi de requêtes : il ajoute
  un petit décalage aléatoire entre chaque requête (pour ne pas ressembler à une machine trop
  régulière) et, surtout, il ralentit tout seul quand le serveur dit « trop de requêtes » (erreurs
  429/503) — en respectant le délai d'attente que le serveur demande. Dès que ça repart bien, il
  réaccélère progressivement.
- Deux nouvelles options en ligne de commande : `--quiet` (lent et discret) et `--aggressive` (rapide
  et bruyant), pour choisir selon la cible autorisée. 7 tests de plus.
- Un export « SARIF ». En plus des rapports HTML et JSON, Hades écrit maintenant un fichier dans un
  format standard (SARIF) que GitHub et les outils d'intégration continue savent lire directement.
  Concrètement : les failles trouvées peuvent s'afficher automatiquement dans l'onglet « Security »
  d'un projet GitHub, avec leur niveau de gravité et leurs étiquettes (CWE/OWASP). 6 tests de plus.
- Une « CI » (vérification automatique). J'ai ajouté une configuration GitHub Actions qui relance
  tout seul, à chaque modification envoyée sur GitHub, le contrôle des imports et les 435 tests —
  sur trois versions de Python (3.10, 3.11, 3.12). Si quelque chose casse, GitHub le signale tout de
  suite, ce qui protège la règle « ne jamais casser la branche principale ».

**Les mots nouveaux**

- **Faille vérifiée** : une faille dont Hades a la preuve directe, par opposition à une faille
  seulement « soupçonnée » à partir d'indices. Un pentester peut donc traiter en priorité ce qui est
  certain.
- **XSS** : une faille qui permet d'injecter du code (JavaScript) dans une page, exécuté chez la victime.
- **SSTI** (Server-Side Template Injection) : le serveur « calcule » du texte fourni par l'utilisateur
  comme s'il s'agissait de code de template — ça mène souvent à l'exécution de commandes.
- **SSRF** (Server-Side Request Forgery) : on force le serveur à aller chercher une URL à notre place,
  ce qui permet d'atteindre des services internes normalement inaccessibles.

**Les mots nouveaux (suite)**

- **Couverture (coverage)** : la liste honnête de ce qu'un scan a examiné. Un rapport « tout va
  bien » n'a pas la même valeur si l'outil a tout testé ou s'il n'a touché qu'une petite partie du
  site. La couverture rend cette différence visible.
- **Surface d'attaque** : l'ensemble des endroits où une attaque est possible (pages, paramètres
  d'URL, formulaires). Plus la surface explorée est grande, plus le scan est complet.
- **429 / 503** : des codes d'erreur que renvoie un serveur quand il est débordé (« ralentis ! »).
  Un bon outil les écoute et lève le pied, au lieu de continuer à cogner.
- **Jitter (gigue)** : un petit délai aléatoire ajouté entre les requêtes pour que le trafic
  paraisse moins « robotique » et déclenche moins les systèmes de défense.
- **SARIF** : un format de fichier standard pour partager des résultats d'analyse de sécurité.
  Beaucoup d'outils (dont GitHub) le comprennent, donc produire du SARIF rend Hades compatible avec
  eux sans effort supplémentaire.
- **CI (intégration continue)** : un système qui vérifie automatiquement le code à chaque
  modification. Lui donner du SARIF permet de bloquer ou signaler les failles au bon moment.

**Pourquoi ça compte**

Dans un rapport, séparer ce qui est *prouvé* de ce qui est *probable* fait gagner un temps énorme :
le pentester sait tout de suite quelles failles sont du solide à montrer au client, sans devoir
re-tester à la main. Et la couverture évite le piège du faux sentiment de sécurité : un rapport
propre après un scan partiel n'est pas une preuve que le site est sûr. Ces deux ajouts sont des
marqueurs de sérieux qu'on retrouve dans les outils professionnels.

**La suite**

La **reprise de scan** (`--resume`) : permettre à un scan interrompu de repartir là où il s'était
arrêté au lieu de tout recommencer. C'est un chantier plus délicat (il touche au cœur du moteur qui
lance les tests en parallèle), donc il mérite une session dédiée.
