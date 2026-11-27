# Journal de bord — Hades

> Un résumé en français simple de ce qui est ajouté à Hades chaque jour.
> Objectif : que Yann comprenne l'évolution de l'outil sans avoir à lire le code.
> Entrée la plus récente en haut.

## 2026-11-27 (bloquer un pipeline, export tableur, et la famille `.well-known`)

**Ce que j'ai ajouté aujourd'hui**

- **Option `--fail-on <gravité>` (le « feu rouge » pour l'intégration continue)** : on peut maintenant
  dire à Hades « si tu trouves quelque chose d'au moins aussi grave que *high*, échoue ». Concrètement,
  Hades renvoie un **code d'erreur** (3) au lieu de 0. C'est ce qui permet de **bloquer automatiquement
  une mise en production** : si le scan trouve une faille sérieuse, la chaîne d'automatisation s'arrête
  toute seule. C'est exactement ce que font des outils reconnus comme `nuclei`. Hades respecte aussi la
  liste des fausses alertes (`.hadesignore`), et si on écrit une gravité qui n'existe pas, il ne bloque
  rien (pour ne jamais casser un pipeline à cause d'une faute de frappe).
- **Export CSV (fichier tableur)** : à chaque scan, Hades écrit aussi un fichier `.csv` — une ligne par
  faille, avec les colonnes utiles pour trier (gravité, module, titre, CWE, OWASP, « vérifié ? », URL…).
  On l'ouvre direct dans Excel ou Google Sheets, ou on l'importe dans un outil de suivi de tickets, pour
  faire le tri des findings à plusieurs.
- **Nouveau module `wellknown` (la famille des fichiers `.well-known`)** : en plus de `security.txt`,
  Hades inspecte maintenant trois autres fichiers standard qu'un site peut publier :
  - **change-password** : un raccourci standard vers la page « changer mon mot de passe » (bon signe de
    maturité s'il existe) ;
  - **mta-sts.txt** : la règle de sécurité des e-mails entrants. Si elle est en mode « enforce », les
    e-mails sont forcés en chiffré (bien). Si elle est en mode « testing » ou absente de règle, Hades
    prévient que le chiffrement n'est **pas réellement imposé** ;
  - **openid-configuration** : la « carte » du système de connexion (OpenID Connect). Hades la liste
    comme information de reconnaissance, et surtout il **alerte en MEDIUM** si ce système accepte des
    jetons **non signés** (l'algorithme `none`) — c'est une vraie faiblesse qui permettrait à un
    attaquant de se faire passer pour un autre utilisateur.
  Ce module ne dit rien quand ces fichiers n'existent pas, pour ne pas polluer le rapport.

**Les mots nouveaux**

- **Pipeline / intégration continue (CI)** : la chaîne automatique qui teste et déploie le code à chaque
  modification. Un « code d'erreur » non nul l'arrête.
- **Code de sortie (exit code)** : le nombre qu'un programme renvoie en terminant — 0 = tout va bien,
  autre chose = problème. C'est le signal que la CI lit pour décider de continuer ou non.
- **CSV** : un format de tableau tout simple (valeurs séparées par des virgules) que tous les tableurs
  savent ouvrir.
- **MTA-STS (RFC 8461)** : une règle publiée par un domaine pour forcer le chiffrement (TLS) des e-mails
  qu'on lui envoie, afin d'empêcher qu'ils soient lus ou détournés en route.
- **OpenID Connect / `alg:none`** : un standard de connexion par jeton. « alg:none » veut dire « jeton
  sans signature » : si le serveur l'accepte, n'importe qui peut fabriquer un faux jeton.

**Pourquoi ça compte**

Hades devient utilisable **dans une chaîne automatique** (il peut bloquer un déploiement risqué) et ses
résultats sortent maintenant dans les formats où les équipes travaillent vraiment (tableur, ticket). Le
nouveau module élargit la reconnaissance vers l'e-mail et l'authentification, avec une vraie alerte de
sécurité sur les jetons non signés. Trois ajouts indépendants, testés, sans jamais casser `main`.

**La suite**

Les prochaines grandes cases sont les capacités « actives » derrière `--exploit` (confirmation hors-bande
des SSRF/XXE, confirmation d'IDOR) ; j'ai sciemment laissé de côté la reprise de scan (`--resume`) car
elle touche au cœur du moteur et le projet préfère ne pas risquer un état incomplet sur `main`.

## 2026-11-26 (un nouveau module + trois outils de confort)

**Ce que j'ai ajouté aujourd'hui**

- **Contrôle du fichier `security.txt`** (nouveau module `security_txt`) : beaucoup de sites publient
  un petit fichier standard (`/.well-known/security.txt`) qui dit « voici comment nous signaler une
  faille ». Hades vérifie maintenant s'il existe, s'il est bien à la bonne adresse, s'il contient une
  adresse de contact, et surtout s'il n'est pas **périmé**. Un site sérieux a ce fichier à jour ; son
  absence ou son expiration est une remarque classique dans un rapport. C'est de la **détection
  seulement** : Hades lit un fichier public, il ne touche à rien.
- **Rapport au format Markdown** : à chaque scan, Hades écrit désormais aussi un fichier `.md` en plus
  du HTML et du JSON. Le Markdown se colle directement dans un ticket, une « issue » GitHub ou un
  e-mail client — avec le score, un tableau du nombre de failles par gravité, et une fiche par faille
  (preuve, commande `curl` pour reproduire, correction). Plus besoin de recopier à la main.
- **Liste d'exceptions `.hadesignore`** (option `--ignore-file`) : quand on a vérifié qu'une alerte est
  une **fausse alerte**, on l'écrit une fois dans un fichier `.hadesignore` (par module, par identifiant,
  par empreinte, ou par titre). Aux scans suivants, Hades l'enlève **avant** de calculer la note et
  d'écrire les rapports — donc les fausses alertes ne polluent plus le résultat ni le score. C'est
  l'équivalent d'un `.gitignore`, mais pour les findings.
- **Option `--diff-only`** : utilisée avec `--retest` (le re-scan qui compare à la fois précédente),
  elle n'affiche que les failles **nouvelles** depuis le dernier scan. Pratique pour un re-test : on voit
  tout de suite ce qui a changé, sans relire toute la liste. La note, elle, continue de refléter l'état
  complet du site.

**Les mots nouveaux**

- **security.txt (RFC 9116)** : un fichier texte standard où une entreprise explique comment lui
  signaler une faille de sécurité (adresse de contact, politique, clé de chiffrement).
- **Markdown** : un format texte simple (celui des README GitHub) qui s'affiche joliment avec des
  titres, des tableaux et des blocs de code une fois collé.
- **Fausse alerte (faux positif)** : une faille signalée par l'outil mais qui n'en est pas une après
  vérification humaine.
- **Empreinte (fingerprint)** : un petit code unique qui identifie une faille d'un scan à l'autre, même
  si le reste du rapport change.
- **Re-test / diff** : refaire le même scan plus tard et comparer pour voir ce qui a été corrigé, ce qui
  reste, et ce qui est nouveau.

**Pourquoi ça compte**

Un vrai pentester ne livre pas juste une liste brute : il doit la **partager** (Markdown), **écarter le
bruit** (`.hadesignore`) et **suivre les corrections dans le temps** (`--diff-only`). Ces trois ajouts
rendent le résultat de Hades plus pro et plus utilisable au quotidien, pendant que le module
`security.txt` élargit encore la couverture avec un contrôle que des outils reconnus (Mozilla Observatory,
nuclei) font aussi.

**La suite**

Ajouter une option `--fail-on <gravité>` : faire échouer volontairement un scan (code de sortie ≠ 0)
quand une faille grave est présente, pour bloquer automatiquement une chaîne d'intégration continue (CI).

## 2026-11-25 (soir — deux nouveaux modules de détection)

**Ce que j'ai ajouté aujourd'hui**

- **Injection d'en-tête Host** (`host_header`) : beaucoup de sites fabriquent leurs liens (lien de
  réinitialisation de mot de passe, redirections, balise canonique) à partir de l'en-tête « Host » de
  la requête. Si on peut y mettre n'importe quel domaine et qu'il revient dans la réponse, c'est un
  problème. Hades envoie un faux domaine unique (un « témoin ») dans l'en-tête Host, puis dans les
  en-têtes `X-Forwarded-Host` et consorts, et regarde s'il réapparaît : dans une redirection
  (`Location`) → risque moyen (empoisonnement du lien de reset / redirection ouverte), dans le corps
  de la page → risque faible (candidat à l'empoisonnement de cache). **Détection seulement** : Hades
  signale le reflet, il n'essaie pas vraiment d'empoisonner un cache (ça resterait derrière `--exploit`).
  Le témoin étant unique et bidon, aucune fausse alerte possible.
- **Indicateurs de désérialisation** (`deser_detect`) : quand une appli « désérialise » (reconstruit
  un objet depuis) des données venues du client sans précaution, un attaquant peut parfois exécuter du
  code (RCE). Le signe révélateur : un paramètre, un cookie ou un champ caché qui contient un objet
  sérialisé reconnaissable. Hades inspecte ces entrées et reconnaît les formats Java, PHP, pickle
  Python, Marshal Ruby et ViewState .NET. **Heuristique seulement** : il reconnaît le format, il ne
  fabrique aucun exploit et ne désérialise rien. La preuve n'affiche que le format et un court début de
  valeur — jamais la valeur complète (elle pourrait contenir des données sensibles).

**Les mots nouveaux**

- **En-tête Host** : la ligne de la requête qui dit « quel site je veux » ; si le serveur lui fait
  trop confiance pour construire des liens, on peut le tromper.
- **Empoisonnement de cache (cache poisoning)** : forcer le cache d'un site à garder une page piégée,
  qui est ensuite servie à tous les visiteurs suivants.
- **Sérialisation / désérialisation** : transformer un objet en texte pour le transmettre, puis le
  reconstruire. Reconstruire du texte venu d'un inconnu est dangereux.
- **Gadget chain** : l'enchaînement d'objets qu'un attaquant assemble pour qu'une désérialisation
  exécute son code. Hades ne fabrique jamais ça — il repère seulement le blob sérialisé.

**Pourquoi ça compte**

On garde l'équilibre voulu dans la ROADMAP : deux modules de la Track 1 (détection d'abord, sans
option). Ils élargissent la couverture vers deux classes de failles web classiques et à fort impact,
tout en restant strictement du côté « détection » — pas d'exploitation. Les deux arrivent avec leurs
tests, sont câblés dans le profil `full` et la taxonomie (CWE/OWASP/MITRE). La suite de tests passe à
507 au vert.

**La suite**

Il reste des idées en Track 1 (par ex. l'en-tête `security.txt`) et des améliorations de précision en
Track 3. Les capacités actives (Track 2) restent derrière `--exploit`, sur cibles autorisées
uniquement.

---

## 2026-11-25 (après-midi 2 — élargir la couverture de 3 modules d'exposition)

**Ce que j'ai amélioré aujourd'hui**

- **Identifiants par défaut** : Hades reconnaît maintenant une vingtaine d'interfaces d'administration
  de plus (Zabbix, Grafana, SonarQube, MinIO, Keycloak, Jupyter, Airflow, Webmin, pfSense, Splunk…) et
  rappelle leurs identifiants par défaut documentés. Il ne tente jamais de se connecter (ce serait
  intrusif) : il prévient juste « cette interface existe, vérifie que le mot de passe par défaut a été
  changé ».
- **Fichiers sensibles** : ajout de cibles à fort impact, chacune confirmée par le contenu réel du
  fichier (pour éviter les fausses alertes) — l'état Terraform (`terraform.tfstate`, qui peut contenir
  des secrets en clair), la config Kubernetes (`.kube/config`), les identifiants de déploiement SFTP
  des éditeurs (VS Code, Sublime, Atom), la config Spring (`application.properties`), celle de
  phpMyAdmin, et le journal Git (`.git/logs/HEAD`).
- **Fichiers de sauvegarde** : Hades cherche maintenant plus de types d'archives (`.war` Java, `.xz`,
  bases `.sqlite3`/`.db`) et détecte le code source servi « en texte » (suffixes `.txt`/`.inc`). Un
  fichier n'est signalé que si son contenu prouve que c'est une vraie archive/sauvegarde.

**Les mots nouveaux**

- **Identifiants par défaut** : le login/mot de passe livré d'usine avec un logiciel (ex. admin/admin) ;
  s'il n'est pas changé, n'importe qui entre.
- **Terraform / état** : Terraform décrit l'infrastructure ; son fichier « d'état » peut contenir des
  mots de passe et clés en clair — à ne jamais exposer sur le web.
- **Magic bytes** : les premiers octets d'un fichier qui identifient son type (ex. « PK » pour un ZIP) —
  Hades les vérifie pour confirmer qu'une sauvegarde est réelle.

**Pourquoi ça compte**

Ces trois modules cherchent des secrets exposés par erreur — la cause de nombreuses fuites réelles.
Élargir leur catalogue (sans ajouter de fausses alertes, car tout est confirmé par le contenu) rend
Hades nettement plus utile sur des cibles modernes (cloud, conteneurs, CI/CD).

**La suite**

Continuer à durcir d'autres modules (admin_panel, cloud_buckets, http_methods…) au même standard :
plus de couverture réelle, zéro faux positif, tests à l'appui.

## 2026-11-25 (midi — amélioration de 7 modules existants)

**Ce que j'ai amélioré aujourd'hui** (sur des modules qui existaient déjà, pas seulement les miens)

- **En-têtes de sécurité** : Hades repère maintenant une protection « CSP » envoyée seulement en mode
  « rapport » — elle a l'air présente mais ne bloque RIEN (piège classique). Il signale aussi des
  réglages CSP trop larges (scripts autorisés depuis n'importe quel site, styles en ligne, formulaires
  sans restriction).
- **Cookies** : détection des préfixes `__Host-` / `__Secure-` mal configurés. Ces préfixes sont une
  promesse de sécurité ; si les règles ne sont pas respectées, le navigateur **jette le cookie en
  silence** — on croit être protégé alors qu'on ne l'est pas. Hades le dit maintenant.
- **Clickjacking** : correction d'un faux « tout va bien ». Avant, si un site autorisait l'affichage
  dans un cadre « depuis n'importe quel site HTTPS », Hades le considérait à tort comme protégé.
  Corrigé : seule une vraie liste de sites de confiance compte comme une protection.
- **CORS** (partage entre domaines) : ajout des contournements classiques de liste blanche
  (`monsite.com.attaquant.com`, `pasmonsite.com`) — ça attrape les serveurs qui vérifient mal l'origine.
- **Certificats TLS** : Hades signale maintenant les certificats signés avec de vieux algorithmes
  cassés (MD5, SHA-1) et les clés trop petites (RSA/DSA de moins de 2048 bits).
- **JWT (jetons de connexion)** : liste de « mots de passe faibles » élargie (plus de secrets par défaut
  de frameworks testés), et nouvelle alerte quand un jeton contient des données sensibles (mot de passe,
  clé d'API…) — car un JWT n'est PAS chiffré, juste signé : tout le monde peut le lire.
- **Détection de pare-feu (WAF/CDN)** : une vingtaine de nouvelles signatures (AWS WAF, Azure, Google,
  Fastly, Citrix, Fortinet, Imperva par cookie, etc.).
- **Chaîne de redirections** : Hades alerte maintenant si une redirection transporte un jeton ou un
  secret dans l'URL (code OAuth, identifiant de session…) — surtout grave quand c'est envoyé vers un
  autre domaine, car l'URL fuit dans l'historique, les journaux et l'en-tête « Referer ».
- **DNS / e-mail** : correction d'un bug qui déformait certains noms de domaine (ceux commençant par
  « w »), et nouvelles alertes sur les réglages anti-usurpation faibles : SPF « +all » (laisse
  n'importe qui envoyer des mails au nom du domaine) et DMARC « p=none » (surveille mais ne bloque
  rien).

**Les mots nouveaux**

- **CSP (Content-Security-Policy)** : une règle qui dit au navigateur quelles ressources il a le droit
  de charger — une défense clé contre le XSS.
- **Préfixe de cookie `__Host-`** : un préfixe spécial qui force le navigateur à n'accepter le cookie
  que s'il est bien sécurisé ; sinon il le refuse.
- **CORS** : le mécanisme qui autorise (ou non) un site A à lire les données d'un site B depuis le
  navigateur. Mal configuré, il laisse fuiter des données entre domaines.
- **WAF** : un pare-feu applicatif web, qui filtre les requêtes malveillantes devant un site.

**Pourquoi ça compte**

Un scanner crédible ne se juge pas qu'au nombre de types de failles, mais à la **justesse** de chaque
module. Ces 7 améliorations corrigent des angles morts (protections qui n'en sont pas) et élargissent
la détection sur des réglages très courants — le tout avec ~30 nouveaux tests pour éviter les
régressions.

**La suite**

Deux idées ajoutées au backlog : la détection de « confusion d'algorithme » JWT (RS256→HS256) et un
contrôle `security.txt` / `.well-known`. Sinon, continuer à durcir les modules restants.

## 2026-11-25 (soir — nouveau tour de renforcement)

**Ce que j'ai ajouté aujourd'hui**

- **SSTI plus fiable (injection de template).** Ce module vérifie si le serveur *calcule* une
  multiplication qu'on lui glisse (par ex. `9787 × 7919 = 77523853`) : si le résultat apparaît, c'est
  qu'il exécute notre code. J'ai ajouté un garde-fou : avant de crier « faille », Hades vérifie que ce
  nombre n'était pas *déjà* présent sur la page (ça pourrait être un vrai numéro de commande). Résultat :
  moins de fausses alertes. J'ai aussi ajouté deux nouvelles syntaxes de template reconnues (Smarty et
  Mako), donc Hades détecte plus de moteurs.
- **Redirections ouvertes mieux détectées.** Une « redirection ouverte », c'est quand un site peut être
  forcé à renvoyer le visiteur vers n'importe quel autre site (utile pour le phishing). Avant, Hades ne
  testait qu'une seule forme d'attaque ; maintenant il en essaie plusieurs (`//site`, `https:/site`,
  antislash, `utilisateur@site`…), car beaucoup de sites bloquent la forme évidente mais oublient les
  variantes. Il détecte donc des cas qu'il ratait avant.
- **Filet de sécurité sur les rapports.** J'ai écrit une série de tests qui « verrouillent » le format
  du rapport JSON (le fichier de résultats lisible par d'autres outils) : score, note, nombre de failles
  par gravité, données de couverture, et le statut « vérifié » de chaque faille. Si un jour une
  modification casse ce format par accident, un test échouera tout de suite.
- **Tests.** 6 nouveaux tests. La suite passe de 460 à **466 tests**, tous au vert.

**Les mots nouveaux**

- **SSTI (Server-Side Template Injection)** : une faille où une donnée de l'utilisateur est traitée
  comme du code de « gabarit » côté serveur, ce qui mène souvent à l'exécution de commandes.
- **Redirection ouverte** : un paramètre d'URL qui permet d'envoyer le visiteur vers un site externe
  arbitraire — classique pour le hameçonnage (le lien commence sur un site de confiance).
- **Garde-fou / baseline** : une mesure de référence « avant attaque » à laquelle on compare, pour être
  sûr que c'est bien notre test qui a provoqué le changement — et pas un hasard.

**Pourquoi ça compte**

Toujours la même logique : un bon scanner détecte plus de vraies failles **et** signale moins de
fausses. Ce tour améliore les deux côtés (SSTI et redirections) et ajoute un filet de sécurité pour que
le format des rapports reste stable dans le temps.

**La suite**

Finir le durcissement anti-faux-positifs sur les derniers modules, puis repartir sur le Track 1
(nouveaux modules : injection d'en-tête Host / cache-poisoning, indices de désérialisation).

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
