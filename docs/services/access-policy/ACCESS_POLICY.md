# Institutional access policies

This guide describes the optional institutional policy that restricts access to
lab categories. It is an off-chain authorization gate around reservation intents;
it does not replace Marketplace authentication, WebAuthn, wallet authorization
or the Diamond's on-chain checks.

## Enforcement model

The policy is evaluated at three useful points:

1. Marketplace can evaluate a lab before submitting a reservation intent.
2. The backend checks a reservation intent during authorization and submission.
3. The execution worker re-checks the durable intent immediately before its
   on-chain transaction.

The last check matters: a previously allowed preflight must not become a way to
bypass a policy update or a stale identity context. A denial returns
`LAB_CATEGORY_ACCESS_DENIED`; an unavailable policy or metadata dependency is a
retryable service failure.

The policy is considered only for a positive-priced lab. A missing or disabled
profile, a lab with no positive price, or a request with no applicable profile
does not restrict the reservation. When an enabled profile cannot resolve the
institutional identity context, the evaluation denies with
`IDENTITY_CONTEXT_UNAVAILABLE`.

## Policy semantics

Each institution has one versioned profile, stored by its configured
`provider.organization`. A profile contains:

- `enabled` and a `defaultDecision` (`ALLOW` or `DENY`);
- groups with attribute matchers and allowed/denied categories;
- category overrides, also expressed as `ALLOW` or `DENY`.

Matcher keys are compared case-insensitively after removing punctuation. All
matcher keys in a group must match; values within one key are alternatives.
Values are case-insensitive and may use a trailing `*` wildcard. Categories are
normalised before comparison. When both an allow and a deny match the same
category, the allow match wins because it is evaluated first.

The response identifies the policy version, matched groups/categories and a
stable reason code. The display message is intentionally generic for denials;
do not expose group membership or identity attributes to end users.

## Administrative API

The profile API is served to the wallet dashboard and uses the same
localhost/private-network and access-token boundary as other wallet and billing
administration routes. The institution ID is derived from the persisted pairing
configuration; callers cannot edit it to manage another institution.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/wallet-admin/access-policies` or `/effective` | Read the current profile and recent audit entries. |
| `GET` | `/wallet-admin/access-policies/{institutionId}` | Read the current institution profile when the ID matches the configured institution. |
| `PUT` | `/wallet-admin/access-policies` or `/{institutionId}` | Replace the profile and increment its version. |
| `POST` | `/wallet-admin/access-policies/activate` or `/deactivate` | Enable or disable the current profile. |
| `POST` | `/wallet-admin/access-policies/test` | Evaluate sample attributes, price and categories without a booking. |
| `GET` | `/wallet-admin/access-policies/export` | Export the current profile. |
| `POST` | `/wallet-admin/access-policies/import` | Import a profile as a new local version. |
| `GET` | `/wallet-admin/access-policies/audit?limit=50` | Read policy change events. |

The `{institutionId}` variants of update, activation, test and import are
available only for the configured institution. Profile writes are audited with
the new version and the `wallet-dashboard` actor.

## Evaluation API

Evaluation routes are routable through Spring Security so that Marketplace can
call them, but they enforce the service JWT and institutional session
credential themselves:

| Method | Path | Required proof |
| --- | --- | --- |
| `POST` | `/access-policy/labs/evaluate` | Marketplace JWT with `access-policy:evaluate`; JSON body includes `institutionalSessionToken`, `labId`, `price` and optional `categories`. |
| `GET` | `/access-policy/labs/{labId}/eligibility` | The same Marketplace scope, `X-Institutional-Session`, and optional `price`/`categories` query parameters. |
| `POST` | `/access-policy/labs/eligibility:batch` | The same scope, one institutional session token and at most 100 evaluations. |

When a profile is enabled, the backend obtains the category from the lab
metadata registered for that lab instead of trusting a caller-provided category
list. Do not treat the optional category hint as authoritative.

## Identity and persistence

The backend stores a hashed identity reference and the small set of normalised
attributes needed for matching. Raw SAML/OIDC tokens, assertions and bearer
credentials are not stored in the policy context. The current main-branch
session exchange populates the context from validated SAML at
`POST /auth/saml/session`; the model also has an OIDC adapter for the
OIDC/Entra integration that is being brought into the main line. OIDC discovery
and JWKS documentation must therefore remain intact, but discovery alone is not
an OIDC session endpoint.

The profile, identity context and audit tables are created by Flyway migration
`V57__institutional_access_policies.sql`. Production deployments must keep
MySQL persistent and healthy so that policy versions and identity contexts are
consistent across restarts and replicas.

See [Authentication](../authentication/AUTH.md) for session credentials,
[Wallet/Billing](../wallet/WALLET_BILLING.md) for the administrative boundary,
and the [API reference](../../reference/API_REFERENCE.md) for the complete
controller index.
