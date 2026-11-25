# Journal de bord — Hades

> Un résumé en français simple de ce qui est ajouté à Hades chaque jour.
> Objectif : que Yann comprenne l'évolution de l'outil sans avoir à lire le code.
> Entrée la plus récente en haut.

## 2026-11-25 (après-midi — renforcement des modules existants)

**Ce que j'ai ajouté aujourd'hui**

- **Moins de fausses alertes (très important).** J'ai créé un détecteur central de « pages de blocage »
  — ces pages d'erreur qu'un pare-feu applicatif (WAF) renvoie quand il bloque une requête. Problème :
  certains tests de Hades concluent « faille ! » juste parce que deux requêtes donnent des réponses
  *différentes*. Or si le WAF bloque l'une et laisse passer l'autre, la différence est factice.
  Maintenant, l'injection SQL « à l'aveugle » et l'injection NoSQL ignorent ces cas → beaucoup moins
  de fausses alertes, donc des rapports plus crédibles.
- **Détection XSS plus fine.** J'ai appris à Hades un nouveau cas : quand une donnée est reflétée dans
  un « gabarit de texte » JavaScript (entre accents graves `` ` ``). Avant, Hades risquait de crier à
  tort à la faille dans ce cas ; maintenant il vérifie le vrai motif dangereux (`${...}`). J'ai aussi
  ajouté des variantes d'attaque par contexte (balise SVG, injection d'un gestionnaire d'événement)
  pour contourner les filtres naïfs — sans jamais baisser le niveau de preuve exigé.
- **Détection LFI élargie.** Le module qui repère la lecture de fichiers interdits sait maintenant
  essayer plus de variantes : traversées de dossier doublement encodées, chemins Windows absolus et à
  antislash encodé (`win.ini`), et plus de « wrappers PHP » pour récupérer le code source (dont
  `config.php` et `wp-config.php`). La confirmation reste basée sur le *contenu réel du fichier*, donc
  on élargit la couverture sans ajouter de fausses alertes.
- **Tests.** 10 nouveaux tests automatiques, dont des tests « anti-régression » qui garantissent que
  les fausses alertes de WAF ne reviendront pas.

**Les mots nouveaux**

- **WAF (Web Application Firewall)** : un pare-feu qui filtre les requêtes vers un site et bloque
  celles qui ressemblent à une attaque, souvent en renvoyant une page « accès refusé ».
- **Faux positif** : quand un outil signale une faille qui n'existe pas en réalité. On cherche à en
  avoir le moins possible.
- **Gabarit de texte JS (template literal)** : une chaîne de caractères en JavaScript écrite entre
  accents graves `` `…` ``, dans laquelle `${expression}` exécute du code — d'où le risque XSS.

**Pourquoi ça compte**

Un scanner qui crie « faille ! » à tort fait perdre du temps et perd la confiance de celui qui l'utilise.
En réduisant les fausses alertes et en élargissant les vraies détections (XSS et LFI), Hades devient à
la fois plus fiable et plus complet — exactement ce qu'on attend d'un outil sérieux.

**La suite**

Continuer le Track 3 : augmenter encore la couverture de tests sur les modules de rapport
(`scanner/output/*`), puis reprendre le Track 1 (en-tête Host / cache-poisoning, désérialisation).

## 2026-11-25

**Ce que j'ai ajouté aujourd'hui**

- **Détection des failles XXE** (XML External Entity). Quand un site accepte du XML (formulaires,
  API, services SOAP…), Hades lui envoie désormais un XML piégé pour voir si le serveur se laisse
  manipuler. S'il arrive à lire un fichier interne du serveur (comme la liste des comptes `/etc/passwd`),
  c'est une preuve solide marquée en gravité « HAUTE ». Il y a aussi un test « canari » totalement
  inoffensif qui vérifie juste si le serveur traite les entités XML (le signe avant-coureur d'une XXE).
- **Détection des injections NoSQL** (bases de données type MongoDB). Certaines applis modernes
  n'utilisent pas du SQL classique mais des bases « NoSQL ». Hades sait maintenant repérer quand on
  peut glisser des « opérateurs » dans une requête (par exemple « différent de » au lieu de « égal à »)
  pour contourner une page de connexion ou lire des données qu'on ne devrait pas voir. Il confirme la
  faille en comparant deux réponses du serveur, donc il ne crie pas « faille ! » à tort.
- **Reconnaissance des API GraphQL**. GraphQL est une façon moderne de construire des API. Hades
  cherche maintenant les points d'entrée GraphQL (`/graphql`, etc.) et vérifie trois mauvais réglages
  fréquents : si le plan complet de l'API est téléchargeable par n'importe qui (« introspection »), si
  les messages d'erreur soufflent des noms de champs (« Did you mean… »), et il rappelle de limiter la
  profondeur des requêtes.
- Pour chacun de ces trois modules : branchement dans le profil de scan `full`, étiquettes
  professionnelles (CWE / OWASP) pour que les rapports soient crédibles, lien vers les « playbooks »
  d'exploitation correspondants, et des tests automatiques (17 au total) pour que ça reste fiable.

**Les mots nouveaux**

- **XXE (XML External Entity)** : une faille où un serveur qui lit du XML peut être forcé à ouvrir des
  fichiers internes ou à contacter d'autres machines à la place de l'attaquant.
- **Injection NoSQL** : comme l'injection SQL, mais pour les bases de données modernes (MongoDB…) ;
  on injecte des « opérateurs » plutôt que du texte pour tromper la requête.
- **GraphQL / introspection** : GraphQL est un langage de requêtes pour API ; l'« introspection » est
  une fonction pratique pour les développeurs qui, laissée active en production, livre tout le plan de
  l'API à un attaquant.

**Pourquoi ça compte**

Ces trois ajouts élargissent nettement la couverture de Hades vers des technologies très présentes
dans les applis web d'aujourd'hui (API JSON/XML, bases NoSQL, GraphQL). Un pentester qui lance Hades
sur une cible autorisée verra maintenant des catégories de failles que l'outil ignorait hier — le tout
en mode détection, sans rien casser côté serveur.

**La suite**

Continuer la feuille de route Track 1 (nouveaux modules de détection) avec l'injection d'en-tête Host
/ indices de cache-poisoning, puis les indices de désérialisation non sécurisée — en gardant l'équilibre
avec le Track 3 (améliorer la précision des modules existants).

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
  tout seul, à chaque modification envoyée sur GitHub, le contrôle des imports et les tests —
  sur trois versions de Python (3.10, 3.11, 3.12). Si quelque chose casse, GitHub le signale tout de
  suite, ce qui protège la règle « ne jamais casser la branche principale ».
- Bonus : dès sa première exécution, la CI a trouvé un vrai bug caché — un bout de code qui marchait
  sur Python 3.12 mais plantait sur 3.10/3.11, alors que le projet promet de fonctionner à partir de
  3.10. Je l'ai corrigé et ajouté un test pour qu'il ne revienne jamais. La CI justifie déjà son
  existence.

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
