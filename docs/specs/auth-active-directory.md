# Spec — Authentification Active Directory (LDAP)

> Statut : proposition · Date : 2026-09-26
> Périmètre : `server/` (back) et `frontend/` (front)

## 1. Objectif

Permettre aux utilisateurs de se connecter à AnythingLLM avec leur compte Active Directory (identifiant + mot de passe Windows), sans créer de compte manuellement au préalable.

**Dans le périmètre**
- Connexion par bind LDAP/LDAPS sur un contrôleur de domaine AD.
- Création automatique du compte local à la première connexion (provisioning « just-in-time »).
- Restriction d'accès par groupe AD, et rôle AnythingLLM (`admin` / `manager` / `default`) déduit des groupes AD.
- Cohabitation avec les comptes locaux existants (compte admin de secours).

**Hors périmètre (V1)**
- SSO transparent Kerberos/NTLM (connexion sans saisie du mot de passe).
- SAML / OIDC (Entra ID / Azure AD). La conception laisse la place à d'autres fournisseurs via le champ `auth_provider`.
- Synchronisation complète de l'annuaire (import en masse).

## 2. Existant (à connaître avant de commencer)

| Élément | Emplacement | Rôle actuel |
|---|---|---|
| Login | [server/endpoints/system.js:198](../../server/endpoints/system.js#L198) `POST /request-token` | Mode multi-utilisateur : cherche `users.username`, compare en bcrypt, renvoie un JWT `{id, username}`. Mode mono-utilisateur : compare avec `AUTH_TOKEN`. |
| JWT | [server/utils/http/index.js:25](../../server/utils/http/index.js#L25) `makeJWT` / `decodeJWT` | Signé avec `JWT_SECRET`, durée `JWT_EXPIRY` (30 j par défaut). |
| Contrôle des requêtes | [server/utils/middleware/validatedRequest.js](../../server/utils/middleware/validatedRequest.js) | Décode le JWT, recharge l'utilisateur, refuse s'il est `suspended`. |
| Rôles | [server/utils/middleware/multiUserProtected.js](../../server/utils/middleware/multiUserProtected.js) | `admin`, `manager`, `default`. |
| Modèle utilisateur | [server/models/user.js](../../server/models/user.js), table `users` dans [schema.prisma:61](../../server/prisma/schema.prisma#L61) | `password` est **non nullable** ; `username` doit respecter `^[a-z][a-z0-9._@-]*$` (2 à 64 caractères). |
| SSO simple | [server/utils/middleware/simpleSSOEnabled.js](../../server/utils/middleware/simpleSSOEnabled.js), `GET /request-token/sso/simple` | Jetons temporaires émis par un système tiers. `SIMPLE_SSO_NO_LOGIN` désactive le login par identifiants. |
| Réglages exposés au front | [server/models/systemSettings.js:630](../../server/models/systemSettings.js#L630) | `SimpleSSOEnabled`, etc., lus par `System.keys()` côté front. |
| Clés d'env persistées | [server/utils/helpers/updateENV.js:1551](../../server/utils/helpers/updateENV.js#L1551) | Liste des clés conservées lors de la réécriture du `.env`. |
| Front login | [frontend/src/pages/Login/index.jsx](../../frontend/src/pages/Login/index.jsx), [frontend/src/components/Modals/Password/MultiUserAuth.jsx](../../frontend/src/components/Modals/Password/MultiUserAuth.jsx) | Formulaire identifiant/mot de passe, récupération par codes de secours. |

**Conséquence de conception :** l'AD ne sert qu'à **vérifier l'identité au moment du login**. Ensuite, on émet le JWT habituel pour un utilisateur local rattaché. Tout le reste (middlewares, rôles, droits sur les workspaces) fonctionne sans modification.

## 3. Principe de fonctionnement

```
Utilisateur ──(identifiant, mot de passe)──▶ POST /request-token
                                                │
                     LDAP_ENABLED ? ─── non ───▶ flux local actuel (bcrypt)
                                                │ oui
                                                ▼
             1. bind compte de service (LDAP_BIND_DN)
             2. recherche de l'utilisateur (LDAP_USER_FILTER, filtre échappé)
             3. bind avec le DN trouvé + mot de passe saisi  ← vérifie le mot de passe
             4. contrôle d'appartenance à LDAP_REQUIRED_GROUP_DN (groupes imbriqués inclus)
             5. calcul du rôle (groupes admin / manager)
             6. recherche/création du user local (auth_provider = "ldap", external_id = objectGUID)
             7. user.suspended ? refus
             8. makeJWT({ id, username }) → même réponse que le login local
```

**Ordre de résolution quand AD est activé :**
1. Si un utilisateur local existe avec ce `username` et `auth_provider = "local"`, et que `LDAP_ALLOW_LOCAL_LOGIN` est actif : flux bcrypt actuel (compte de secours).
2. Sinon : flux AD.
3. Un utilisateur `auth_provider = "ldap"` ne peut **jamais** se connecter par bcrypt.

## 4. Configuration (variables d'environnement)

La configuration passe uniquement par l'environnement, comme pour le SSO simple. Le mot de passe du compte de service ne transite donc jamais par l'interface.

| Variable | Obligatoire | Exemple / défaut | Description |
|---|---|---|---|
| `LDAP_ENABLED` | oui | `1` | Active le flux AD (effectif seulement en mode multi-utilisateur). |
| `LDAP_URL` | oui | `ldaps://dc01.corp.local:636` | Une ou plusieurs URL séparées par des virgules (bascule en cas de panne). |
| `LDAP_BIND_DN` | oui | `CN=svc-anythingllm,OU=Services,DC=corp,DC=local` | Compte de service en lecture seule. |
| `LDAP_BIND_PASSWORD` | oui | — | Mot de passe du compte de service. |
| `LDAP_BASE_DN` | oui | `DC=corp,DC=local` | Base de recherche des utilisateurs. |
| `LDAP_USER_FILTER` | non | `(&(objectCategory=person)(objectClass=user)(sAMAccountName={{username}})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` | `{{username}}` est remplacé par la saisie **échappée** (RFC 4515). Le dernier terme exclut les comptes désactivés. |
| `LDAP_USERNAME_ATTRIBUTE` | non | `sAMAccountName` | Attribut utilisé comme `username` local (converti en minuscules). |
| `LDAP_REQUIRED_GROUP_DN` | non | `CN=GG-AnythingLLM-Users,OU=Groups,DC=corp,DC=local` | S'il est défini, l'appartenance est obligatoire (groupes imbriqués inclus). |
| `LDAP_ADMIN_GROUP_DN` | non | `CN=GG-AnythingLLM-Admins,...` | Membres → rôle `admin`. |
| `LDAP_MANAGER_GROUP_DN` | non | `CN=GG-AnythingLLM-Managers,...` | Membres → rôle `manager`. |
| `LDAP_SYNC_ROLE_ON_LOGIN` | non | `1` | Si actif, le rôle est recalculé à chaque connexion (l'AD fait foi). Sinon, il n'est fixé qu'à la création et reste modifiable dans l'interface. |
| `LDAP_ALLOW_LOCAL_LOGIN` | non | `1` | Autorise les comptes `local` à se connecter (fortement recommandé pour garder un admin de secours). |
| `LDAP_LINK_EXISTING_USERS` | non | non défini | Si actif, un utilisateur local portant le même `username` est rattaché à l'AD à sa première connexion AD. Sinon, la connexion est refusée (évite une prise de contrôle de compte). |
| `LDAP_TLS_CA_PATH` | non | `/app/certs/corp-root-ca.pem` | Autorité de certification de l'AD pour LDAPS. |
| `LDAP_TLS_REJECT_UNAUTHORIZED` | non | `true` | À ne mettre à `false` qu'en environnement de test. |
| `LDAP_STARTTLS` | non | non défini | Utilise StartTLS sur une URL `ldap://`. |
| `LDAP_TIMEOUT_MS` | non | `5000` | Délai maximal de connexion et d'opération. |
| `LDAP_LOGIN_LABEL` | non | `Compte Windows` | Libellé affiché sur l'écran de connexion. |

## 5. Back-end — étapes

### B1. Dépendance
- Ajouter **`ldapts`** à `server/package.json` (client LDAP maintenu, basé sur des promesses). **Ne pas utiliser `ldapjs`**, archivé et plus maintenu.
- Vérifier que le build Docker (`docker/`) l'embarque (pur JS, pas de dépendance native).

### B2. Schéma Prisma et migration
Dans `model users` ([schema.prisma:61](../../server/prisma/schema.prisma#L61)) :
```prisma
auth_provider    String    @default("local")   // "local" | "ldap"
external_id      String?   @unique              // objectGUID AD (base64)
last_ldap_sync   DateTime?
```
- Générer la migration : `cd server && npx prisma migrate dev --name add_user_auth_provider`.
- Les utilisateurs existants deviennent automatiquement `auth_provider = "local"`.
- On identifie l'utilisateur par `external_id` (objectGUID, immuable) et non par le `username`, qui peut changer dans l'AD.

### B3. Modèle `User` ([server/models/user.js](../../server/models/user.js))
- Ajouter `auth_provider` et `external_id` au typedef. Ne **pas** les ajouter à `writable`, pour qu'ils ne soient pas modifiables par l'API.
- Nouvelle méthode `User.upsertFromLdap({ externalId, username, role })` :
  - recherche par `external_id` ; si trouvé, mise à jour du `username` (s'il a changé), du rôle (si `LDAP_SYNC_ROLE_ON_LOGIN`) et de `last_ldap_sync` ;
  - sinon, recherche par `username` : si c'est un compte local, le rattacher seulement si `LDAP_LINK_EXISTING_USERS`, sinon renvoyer une erreur ;
  - sinon, création avec `password = bcrypt(crypto.randomBytes(48))` (colonne non nullable, mot de passe inutilisable) **sans passer par `checkPasswordComplexity`**, et `seen_recovery_codes = true` ;
  - valider le `username` avec `User.validations.username` ; s'il est invalide après conversion en minuscules, refuser avec un message explicite.
- Dans `User.update` : si `auth_provider === "ldap"`, **ignorer/refuser toute modification de `password` et de `username`**, et du `role` si `LDAP_SYNC_ROLE_ON_LOGIN` est actif.
- `filterFields` : conserver `auth_provider` (utile au front), masquer `external_id`.

### B4. Module LDAP — `server/utils/auth/ldap/index.js` (nouveau)
Contenu :
- `isLdapEnabled()` : `"LDAP_ENABLED" in process.env` **et** configuration minimale présente.
- `getLdapConfig()` : lit et valide les variables ; lève une erreur claire au démarrage si une variable obligatoire manque.
- `authenticate(username, password)` → `{ externalId, username, displayName, email, groups, role } | { error }` :
  1. **Refuser un mot de passe vide** avant tout appel : un bind avec mot de passe vide est un bind anonyme que l'AD accepte, donc une connexion sans mot de passe serait possible.
  2. Créer un `Client` `ldapts` (`url`, `timeout`, `connectTimeout`, `tlsOptions` avec CA et `rejectUnauthorized`), puis `startTLS` si configuré.
  3. Bind avec le compte de service.
  4. `search(LDAP_BASE_DN, { scope: "sub", filter, attributes: ["objectGUID", "sAMAccountName", "userPrincipalName", "displayName", "mail", "memberOf"], sizeLimit: 2 })`, avec `{{username}}` **échappé** (utiliser les classes de filtre de `ldapts`, ex. `EqualityFilter`, ou une fonction `escapeFilterValue`).
  5. 0 résultat → échec ; plus d'un résultat → échec (filtre ambigu) avec log serveur.
  6. Bind avec `dn` de l'utilisateur + mot de passe. `InvalidCredentialsError` → échec.
  7. Contrôle des groupes via une recherche utilisant la règle `LDAP_MATCHING_RULE_IN_CHAIN` pour les groupes imbriqués :
     `(&(distinguishedName=<userDN>)(memberOf:1.2.840.113556.1.4.1941:=<groupDN>))` pour chacun des groupes requis, admin et manager.
  8. Rôle : `admin` si membre du groupe admin, sinon `manager` si membre du groupe manager, sinon `default`.
  9. `unbind()` systématique dans un `finally`.
- Convertir `objectGUID` (Buffer) en base64 pour `external_id`.
- Mettre les URL multiples en bascule : essayer la suivante si erreur de connexion (pas si erreur d'identifiants).
- Ne **jamais** journaliser le mot de passe ; journaliser le code d'erreur AD (`data 52e`, `773`, `775`, etc.) côté serveur uniquement.

### B5. Endpoint de login ([server/endpoints/system.js:198](../../server/endpoints/system.js#L198))
Dans la branche multi-utilisateur, avant la recherche locale actuelle :
```js
if (isLdapEnabled()) {
  const local = await User._get({ username: String(username) });
  const useLocal =
    local?.auth_provider === "local" && ldapAllowLocalLogin();
  if (!useLocal) return await ldapLogin(request, response, { username, password });
}
// … flux bcrypt existant (il doit aussi refuser si existingUser.auth_provider === "ldap")
```
`ldapLogin` (dans le même fichier, ou dans `server/utils/auth/ldap/login.js`) :
- appelle `authenticate`, puis `User.upsertFromLdap` ;
- vérifie `suspended` (code `[004]` existant) ;
- journalise `login_event` avec `{ ip, username, provider: "ldap" }` dans `EventLogs`, et `Telemetry.sendTelemetry("login_event", { multiUserMode: true, provider: "ldap" })` ;
- en cas d'échec : `EventLogs.logEvent("failed_login_ldap", { ip, username, reason })` où `reason` est interne (`invalid_credentials`, `not_in_group`, `user_not_found`, `ambiguous`, `link_refused`, `server_unreachable`) ;
- réponse **identique au format actuel** : `{ valid, user, token, message }`. Messages côté client :
  - `[006] Invalid login credentials.` (identifiants erronés **ou** utilisateur introuvable : ne pas distinguer les deux) ;
  - `[007] You are not authorized to access this instance.` (hors du groupe requis) ;
  - `[008] Authentication server unavailable.` (AD injoignable, avec un statut `503`) ;
  - `[009] An account with this username already exists.` (conflit, rattachement refusé).
- Ne pas générer de codes de secours pour un utilisateur `ldap`.

Remarques :
- Si `SIMPLE_SSO_NO_LOGIN` est actif, le login par identifiants (et donc AD) reste bloqué ([system.js:203](../../server/endpoints/system.js#L203)). Documenter ce comportement.
- En mode mono-utilisateur, `LDAP_ENABLED` est ignoré. Afficher un avertissement au démarrage.

### B6. Endpoints de mot de passe à verrouiller
Pour un utilisateur `auth_provider === "ldap"`, renvoyer `400` avec « Password is managed by Active Directory » sur :
- `POST /system/recover-account` ([system.js:395](../../server/endpoints/system.js#L395)) et `POST /system/reset-password` ([system.js:420](../../server/endpoints/system.js#L420)) ;
- `POST /system/user` ([system.js:1251](../../server/endpoints/system.js#L1251)), la mise à jour de son propre profil : rejeter `password` et `username` ;
- `POST /admin/user/:id` ([server/endpoints/admin.js](../../server/endpoints/admin.js)) et l'API développeur `/v1/admin/users/:id` ([server/endpoints/api/admin/index.js](../../server/endpoints/api/admin/index.js)) : mêmes règles, plus le `role` si la synchronisation des rôles est active.

Le blocage dans `User.update` (B3) sert de filet de sécurité, mais les endpoints doivent renvoyer une erreur explicite.

### B7. Exposition au front ([server/models/systemSettings.js:630](../../server/models/systemSettings.js#L630))
Ajouter dans `currentSettings()` :
```js
LdapEnabled: isLdapEnabled(),
LdapLoginLabel: process.env.LDAP_LOGIN_LABEL || null,
LdapAllowLocalLogin: "LDAP_ALLOW_LOCAL_LOGIN" in process.env,
LdapRoleSyncEnabled: "LDAP_SYNC_ROLE_ON_LOGIN" in process.env,
```
**N'exposer aucune autre variable** (ni URL, ni DN, ni mot de passe).

### B8. Persistance des clés d'env ([updateENV.js:1551](../../server/utils/helpers/updateENV.js#L1551))
Ajouter toutes les clés `LDAP_*` à la liste des clés conservées, sous un commentaire `// LDAP / Active Directory`, pour qu'elles ne disparaissent pas du `.env` quand l'interface le réécrit. Ne **pas** les ajouter à `KEY_MAPPING` : elles ne doivent pas être modifiables depuis l'interface.

### B9. Endpoint de diagnostic (admin)
`POST /admin/ldap/test` avec `[validatedRequest, strictMultiUserRoleValid([ROLES.admin])]` :
- sans corps : teste la connexion et le bind du compte de service, puis renvoie `{ success, error }` ;
- avec `{ username }` : effectue aussi la recherche et renvoie `{ found, dn, groups, computedRole }`, sans mot de passe et sans bind utilisateur.

### B10. Révocation des sessions
Le JWT dure 30 jours : un compte désactivé dans l'AD resterait connecté.
- **V1 :** documenter qu'il faut réduire `JWT_EXPIRY` (ex. `12h`) quand l'AD est activé.
- **V1.1 (recommandé) :** job `server/jobs/ldap-sync.js` enregistré dans [server/utils/BackgroundWorkers/index.js](../../server/utils/BackgroundWorkers/index.js), qui s'exécute par exemple toutes les heures. Pour chaque utilisateur `ldap`, il recherche l'utilisateur par `objectGUID`. Si l'utilisateur est introuvable, désactivé ou hors du groupe requis, le job met `suspended = 1`, ce qui déclenche le rejet par `validateMultiUserRequest`. Sinon, il resynchronise le rôle.

### B11. Documentation et exemples
- Ajouter un bloc commenté `LDAP_*` dans [server/.env.example](../../server/.env.example) et [docker/.env.example](../../docker/.env.example), à côté du bloc `SIMPLE_SSO_*`.
- Documenter le montage du certificat de l'autorité de certification dans Docker (`volumes:` + `LDAP_TLS_CA_PATH`).

### B12. Tests (`server/__tests__/`)
Tests unitaires Jest avec `ldapts` simulé (mock) :
- échappement du filtre (`*`, `(`, `)`, `\`, NUL) ;
- mot de passe vide → refus sans appel réseau ;
- 0 ou 2 résultats de recherche → refus ;
- mapping des rôles (admin > manager > default) ;
- `upsertFromLdap` : création, mise à jour par `external_id`, changement de `username`, conflit avec un compte local (avec et sans `LDAP_LINK_EXISTING_USERS`) ;
- `/request-token` : AD activé + compte local de secours, utilisateur `ldap` qui tente bcrypt, utilisateur suspendu, AD injoignable → `503` ;
- endpoints de mot de passe verrouillés pour les utilisateurs `ldap`.

Test d'intégration manuel : conteneur **Samba AD DC** (ex. image `nowsci/samba-domain`), qui reproduit les attributs AD (`sAMAccountName`, `memberOf`, `objectGUID`, règle de chaîne), contrairement à OpenLDAP.

## 6. Front-end — étapes

### F1. Écran de connexion ([MultiUserAuth.jsx](../../frontend/src/components/Modals/Password/MultiUserAuth.jsx))
- Lire `LdapEnabled` / `LdapLoginLabel` via `System.keys()`. Créer un hook `frontend/src/hooks/useLdapAuth.js` sur le modèle de [useSimpleSSO.js](../../frontend/src/hooks/useSimpleSSO.js).
- Si l'AD est actif :
  - libellé du champ identifiant : `LdapLoginLabel` ou `t("login.ldap.username")` (« Identifiant Windows ») ;
  - texte d'aide sous le formulaire : « Utilisez votre identifiant et votre mot de passe Windows » ;
  - pas de changement de l'appel : `System.requestToken({ username, password })` reste identique ;
  - lien « Mot de passe oublié » : remplacer le formulaire de codes de secours par un message « Contactez votre service informatique ». Si `LdapAllowLocalLogin` est actif, conserver un lien secondaire « Récupérer un compte local ».
- Afficher les nouveaux messages `[006]` à `[009]` tels que renvoyés par le serveur (le composant affiche déjà `message`).

### F2. Profil utilisateur ([AccountModal](../../frontend/src/components/UserMenu/AccountModal/index.jsx))
- Si `user.auth_provider === "ldap"` : masquer le champ « nouveau mot de passe » (lignes ~148-153), passer `username` en lecture seule, et afficher un badge ou une note « Compte géré par Active Directory ».
- Le `user` provient de `localStorage` (`AUTH_USER`) : il contiendra `auth_provider` grâce à `filterFields` (B3).

### F3. Administration des utilisateurs ([frontend/src/pages/Admin/Users/](../../frontend/src/pages/Admin/Users/))
- `UserRow` : badge « AD » à côté du nom pour les utilisateurs `ldap`.
- Modale d'édition (`UserRow/EditUserModal`) : pour un utilisateur `ldap`, masquer le mot de passe, verrouiller `username`, et verrouiller `role` avec une info-bulle « Rôle synchronisé depuis les groupes AD » si `LdapRoleSyncEnabled` est actif.
- `NewUserModal` : inchangée (création de comptes locaux). Si l'AD est actif, ajouter une note « Les utilisateurs AD sont créés automatiquement à leur première connexion ».
- La suspension reste possible : elle bloque aussi un utilisateur AD côté AnythingLLM.

### F4. Page Sécurité ([frontend/src/pages/GeneralSettings/Security/index.jsx](../../frontend/src/pages/GeneralSettings/Security/index.jsx))
- Si `LdapEnabled` : encart d'information « Authentification Active Directory active (configurée via les variables d'environnement) ».
- Bouton « Tester la connexion AD » → `POST /admin/ldap/test` (B9) via une nouvelle méthode `Admin.testLdap()` dans `frontend/src/models/admin.js`. Afficher le résultat. Le champ optionnel « Tester un utilisateur » affiche le DN, les groupes et le rôle calculé.
- Si l'AD est configuré mais que le mode multi-utilisateur est désactivé, afficher un avertissement « Active Directory nécessite le mode multi-utilisateur ».

### F5. Traductions (`frontend/src/locales/*/common.js`)
- Nouvelles clés sous `login.ldap.*`, `profile_settings.ldap_managed`, `admin.users.ldap_badge`, `security.ldap.*`.
- Traduire au minimum `en` et `fr`. Pour les autres langues, reprendre l'anglais puis passer `node frontend/src/locales/verifyTranslations.mjs`.

## 7. Sécurité — points de contrôle

- [ ] Mot de passe vide refusé avant tout bind (bind anonyme).
- [ ] Saisie échappée dans le filtre LDAP (injection LDAP).
- [ ] LDAPS ou StartTLS obligatoire hors développement ; `rejectUnauthorized` à `true` par défaut.
- [ ] Même message d'erreur pour « utilisateur inconnu » et « mauvais mot de passe ».
- [ ] Compte de service en lecture seule, mot de passe uniquement dans l'environnement, jamais exposé par `System.keys()`.
- [ ] Pas de rattachement implicite d'un compte local existant (risque de prise de contrôle).
- [ ] Aucun mot de passe dans les logs ni dans `EventLogs`.
- [ ] Limitation de débit sur `/request-token` : absente aujourd'hui. Une attaque par force brute via AnythingLLM pourrait **verrouiller des comptes AD**. Ajouter un limiteur (ex. `express-rate-limit`, par IP et par nom d'utilisateur) dans cette itération.
- [ ] Durée des sessions réduite ou job de synchronisation (B10).

## 8. Découpage proposé

| Lot | Contenu | Dépend de |
|---|---|---|
| 1 | B1, B2, B3, B4 + tests unitaires | — |
| 2 | B5, B6, B7, B8, B11 + tests `/request-token` | 1 |
| 3 | F1, F2, F3, F5 | 2 |
| 4 | B9 + F4 (diagnostic) | 2 |
| 5 | B10 (job de synchronisation), limitation de débit | 2 |

## 9. Critères d'acceptation

1. Avec `LDAP_ENABLED`, un utilisateur AD membre du groupe requis se connecte avec son identifiant Windows. Un compte AnythingLLM est créé avec le bon rôle.
2. Un utilisateur AD hors du groupe requis reçoit `[007]` et aucun compte n'est créé.
3. Un mauvais mot de passe ou un utilisateur inconnu renvoie le même message `[006]`.
4. Le compte admin local de secours se connecte toujours quand `LDAP_ALLOW_LOCAL_LOGIN` est actif.
5. Un utilisateur AD ne peut pas changer son mot de passe ni son identifiant dans AnythingLLM (front et API).
6. Si le contrôleur de domaine est injoignable, la réponse est `[008]` en moins de `LDAP_TIMEOUT_MS`, et les comptes locaux fonctionnent toujours.
7. Après un redémarrage et une modification de réglage via l'interface, les variables `LDAP_*` sont toujours présentes dans le `.env`.
8. Avec la saisie `*)(sAMAccountName=*`, la connexion est refusée et aucun résultat multiple n'est renvoyé.
