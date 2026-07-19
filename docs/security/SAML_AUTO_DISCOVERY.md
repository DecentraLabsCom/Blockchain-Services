# SAML metadata discovery and signature validation

`SamlValidationService` validates the XML signature before exposing identity attributes to the authentication, institutional check-in and intent flows. It discovers signing certificates from IdP metadata; it is not an IdP registry or a replacement for the gateway network boundary.

## Effective trust model

The packaged `application.properties` sets `saml.idp.trust-mode=any` unless `SAML_IDP_TRUST_MODE` is supplied. That is convenient for development, but production deployments should use `whitelist` and configure `saml.trusted.idp`. In whitelist mode every permitted issuer must also have its own `saml.idp.metadata.override` entry; a global override or an assertion-provided URL does not satisfy this requirement. Startup validation rejects an incomplete map.

```mermaid
flowchart TD
    A[Base64 SAML assertion] --> B[Parse XML with XXE protections]
    B --> C[Read Issuer]
    C --> D{trust-mode}
    D -->|whitelist| E{Issuer in saml.trusted.idp?}
    D -->|any| F[Continue with issuer as trust anchor]
    E -->|no| R[Reject]
    E -->|yes| F
    F --> G[Resolve metadata URL]
    G --> H[Validate URL and network target]
    H -->|blocked| R
    H --> I[Fetch metadata]
    I --> J[Extract X.509 signing certificates]
    J --> K{Certificate cache hit?}
    K -->|no| L[Cache by issuer, max 500 entries]
    K -->|yes| M[Use cached certificates]
    L --> N[Verify ds:Signature]
    M --> N
    N -->|invalid| R
    N --> O[Extract PUC and attributes]
    O --> P[Return validated attributes]
```

## Resolution order

For an assertion with issuer `I`, the service resolves the metadata URL in this order:

1. `saml.idp.metadata.override` map entry for `I`.
2. In `any` mode only, the optional global `saml.idp.metadata.url` property.
3. In `any` mode only, `AuthnContext/AuthenticatingAuthority` when it looks like a metadata endpoint.
4. In `any` mode only, an `Extensions/MetadataURL` element.

The whitelist path is therefore deterministic: the issuer is allowed only when
its configured metadata URL is present and its downloaded signing certificate
can be validated. No inline certificate, legacy IdP URL construction or
trust-all metadata fallback is used.

Metadata transport rejects non-HTTPS URLs unless `saml.metadata.allow-http=true`, and blocks loopback, private, link-local and cloud-metadata targets. HTTP timeouts are configured under `saml.metadata.http.*`.

## Certificate cache and rotation

Certificates are cached in memory by issuer in a bounded `ConcurrentHashMap` (maximum 500 issuers). There is no time-based expiry or cross-instance sharing. A process restart or `clearCertificateCache()` refreshes keys; planned key rotation therefore requires an operational cache clear/restart or a deployment that does not rely on stale certificates.

## Configuration

```properties
# Production baseline: every issuer in this map needs a matching metadata URL.
saml.idp.trust-mode=whitelist
saml.trusted.idp={'uned':'https://idp.uned.es','ucm':'https://idp.ucm.es'}

# Required issuer-specific metadata overrides in whitelist mode
saml.idp.metadata.override={'https://idp.uned.es':'https://idp.uned.es/metadata','https://idp.ucm.es':'https://idp.ucm.es/metadata'}
saml.idp.metadata.url=

# Optional per-issuer TLS compatibility profile; default is modern.
saml.idp.metadata.tls-profile={'https://legacy-idp.example':'compatibility'}

# Metadata transport hardening
saml.metadata.allow-http=false
saml.metadata.http.connect-timeout-ms=5000
saml.metadata.http.read-timeout-ms=10000
saml.metadata.http.call-timeout-ms=15000
saml.metadata.health.cache-ms=30000
```

The readiness probe includes `samlMetadata` and downloads metadata for every
whitelisted issuer. Check `GET /actuator/health/readiness` after changing the
map. The setup scripts merge new issuer overrides from the template into an
existing `blockchain-services/.env` without replacing operator-defined values.

## Required identity data and failure modes

Signature verification happens before attributes are returned. The service then derives the stable PUC from `eduPersonPrincipalName` and/or `eduPersonTargetedID`, and resolves institution affiliation from `schacHomeOrganization`, scoped affiliation or email. Missing issuer, an untrusted issuer, blocked metadata, absent certificates, invalid signatures or missing PUC identity are authentication failures.

The service is used by:

- `POST /auth/authorize-and-issue` and `POST /auth/access-credential`;
- `POST /auth/checkin-institutional`;
- `POST /intents` when a SAML assertion is supplied.
