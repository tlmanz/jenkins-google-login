# Google Groups OAuth Security Realm (Jenkins plugin)

Sign in to Jenkins with Google OAuth **or a local username/password**. The user's **direct Google Group memberships**
become Jenkins authorities (as group emails, lowercase), so authorization strategies such
as the Role Strategy plugin can bind roles to Google Groups instead of local users:

```yaml
# role-strategy example: onboarding/offboarding = Google Groups membership changes
- name: "qa"
  entries:
    - group: "jenkins-qa@example.com"     # Google Group email
    - user: "qaautomation"                # local API-token user, still works
```

Group resolution uses the **logged-in user's own OAuth token** against the Cloud Identity
API (`searchDirectGroups`). No service account, no Workspace admin grant, and no
domain-wide delegation are required.

## Operator constraints — read before adopting

- **Flat groups only.** Only *direct* memberships resolve. Nested groups do NOT appear
  (the transitive lookup API requires Workspace Enterprise Standard/Plus or Cloud
  Identity Premium). Add users directly to each `jenkins-*` group.
- **Silent filtering.** Google silently omits groups whose membership the caller is not
  allowed to view. Keep the default member-visibility settings on your `jenkins-*`
  groups. Every login logs the resolved authorities at INFO
  (`Google login: <email> authorities=[...]`), and any user can check
  `<jenkins-url>/securityRealm/whoami` — deliberately reachable without Overall/Read,
  since a user whose groups were filtered may have no permissions at all.
- **Authorities refresh at login**, not in the background. Group membership changes
  apply the next time the user logs in. Successful lookups are cached for 60 seconds to
  absorb login storms.
- **API tokens keep working.** Token authentication is checked against stored Jenkins
  user records independent of the realm; pre-existing local users' tokens survive the
  realm switch. API-token requests carry the group authorities recorded at that user's
  last interactive login (or just `authenticated` for users who never log in
  interactively, e.g. pure automation accounts — keep binding those by `user:` name).
- **Hybrid login page (break-glass).** The standard Jenkins login page keeps its
  username/password form, with a "Sign in with Google" button underneath. Passwords are
  checked against the credentials stored on user records created under the previous
  local-database realm, so if Google OAuth is down or misconfigured, pre-existing local
  admins can still log in. Users who only ever logged in via Google have no stored
  password and cannot use the form. Signup remains disabled; new local passworded users
  cannot be created while this realm is active.

## Google Cloud setup

1. Pick (or create) a GCP project and **enable the Cloud Identity API**.
2. Configure the OAuth consent screen as **Internal** (org-only). Internal apps skip
   Google's sensitive-scope verification and block non-org accounts at consent time.
3. Create an OAuth client (type: Web application) with authorized redirect URI
   `https://<jenkins-url>/securityRealm/finishLogin`.
4. Requested scopes: `openid email profile` and
   `https://www.googleapis.com/auth/cloud-identity.groups.readonly`.

## Jenkins configuration (JCasC)

```yaml
jenkins:
  securityRealm:
    googleGroupsOAuth:
      clientId: "1234567890-abc.apps.googleusercontent.com"
      clientSecret: "${google-oauth-client-secret}"
      hostedDomain: "example.com"                              # required; hd claim check
      groupIncludePattern: "^jenkins-.*@example\\.com$"        # optional authority filter
      onGroupLookupFailure: "DEGRADE"                          # DEGRADE | FAIL
```

- `hostedDomain` (required): logins are rejected unless the verified ID token's `hd`
  claim equals this domain — defense in depth on top of the Internal consent screen.
- `groupIncludePattern` (optional): regex; only matching group emails become
  authorities. Empty = all groups.
- `onGroupLookupFailure`: `DEGRADE` (default) logs the user in with only
  `authenticated` and a loud WARNING; `FAIL` refuses the login. Failures are never
  cached as "no groups".

User id = full email (lowercase). `allowsSignup` is always false.

### Values from environment variables

JCasC interpolates `${VAR}` before binding, so every field can come from the
environment (or any other JCasC secret source, e.g. files under `/run/secrets/`):

```yaml
jenkins:
  securityRealm:
    googleGroupsOAuth:
      clientId: "${GOOGLE_OAUTH_CLIENT_ID}"
      clientSecret: "${GOOGLE_OAUTH_CLIENT_SECRET}"
      hostedDomain: "${GOOGLE_HOSTED_DOMAIN:-example.com}"   # ${VAR:-default} supported
      groupIncludePattern: "${GOOGLE_GROUP_PATTERN:-^jenkins-.*@example\\.com$}"
      onGroupLookupFailure: "${GROUP_LOOKUP_FAILURE_POLICY:-DEGRADE}"
```

Prefer a mounted-secret source over an env var for `clientSecret` (on Kubernetes, a
secret mounted under `/run/secrets/` is referenced by file name, keeps the value out of
the pod spec, and picks up rotations on the next JCasC reload; env-var changes need a
pod restart).

## Building

```bash
./mvnw verify          # build + tests; target/google-groups-oauth.hpi
./mvnw hpi:run         # sandbox Jenkins at http://localhost:8080/jenkins
```

Note: use the bundled Maven Wrapper. The Debian/Ubuntu-packaged Maven
(`apt install maven`) breaks the `hpi` packaging type (its patched sisu cannot discover
the maven-hpi-plugin lifecycle mapping).

## Manual E2E checklist

- Internal consent screen configured; Cloud Identity API enabled; redirect URI matches.
- Flat test group with the test user as a direct member → `/securityRealm/whoami` shows
  the group after login.
- Role Strategy `group:` entry with that group email grants access.
- A nested-group membership does NOT appear (expected — document to your operators).
- An API token created for a pre-existing local user still authenticates.

## License

Apache-2.0
