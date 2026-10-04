package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.intent.IntentPayloadCipher;
import decentralabs.blockchain.util.PucNormalizer;
import io.jsonwebtoken.Claims;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Backend-owned credential used after fresh identity evidence validation. */
@Service
@RequiredArgsConstructor
public class InstitutionalSessionCredentialService {

    private static final String TOKEN_TYPE = "institutional_saml_session";
    private static final String IDENTITY_TOKEN_TYPE = "institutional_identity_session";
    private static final String SUBJECT = "institutional-session";
    public static final String OIDC_ID_TOKEN_HASH_VERSION = "oidc-id-token-keccak-v1";
    public static final String VC_CANONICAL_HASH_VERSION = "vc-canonical-keccak-v1";
    private static final Set<String> SUPPORTED_IDENTITY_PROTOCOLS = Set.of("saml2", "oidc", "vc");
    private static final Set<String> SUPPORTED_IDENTITY_HASH_VERSIONS = Set.of(
        SamlAttestationHashService.HASH_VERSION,
        OIDC_ID_TOKEN_HASH_VERSION,
        VC_CANONICAL_HASH_VERSION
    );
    public static final String SUPPORTED_ASSERTION_HASH_VERSION = SamlAttestationHashService.HASH_VERSION;
    private static final Logger log = LoggerFactory.getLogger(InstitutionalSessionCredentialService.class);

    private final JwtService jwtService;
    private final BackendUrlResolver backendUrlResolver;
    private final IntentPayloadCipher payloadCipher;

    @Value("${auth.institutional-session.ttl-seconds:3600}")
    private long ttlSeconds;

    public IssuedCredential issue(
        String institutionId,
        String puc,
        String stableUserIdMode,
        String samlAssertionHash,
        String samlAssertionHashVersion
    ) {
        String normalizedPuc = requireText(PucNormalizer.normalize(puc), "PUC");
        String normalizedInstitution = requireText(institutionId, "institutionId").toLowerCase(Locale.ROOT);
        String normalizedHash = requireHash(samlAssertionHash);
        String normalizedHashVersion = requireHashVersion(samlAssertionHashVersion);
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plusSeconds(Math.max(60, ttlSeconds));

        Map<String, Object> claims = Map.of(
            "aud", backendUrlResolver.resolveBaseDomain(),
            "sub", SUBJECT,
            "sessionType", TOKEN_TYPE,
            "institutionId", normalizedInstitution,
            "pucCiphertext", payloadCipher.encrypt(normalizedPuc),
            "stableUserIdMode", stableUserIdMode == null ? "" : stableUserIdMode,
            "samlAssertionHash", normalizedHash,
            "samlAssertionHashVersion", normalizedHashVersion,
            "reauthenticationAt", expiresAt.getEpochSecond(),
            "exp", Date.from(expiresAt)
        );

        try {
            String token = jwtService.generateToken(claims, null);
            return new IssuedCredential(
                token,
                normalizedPuc,
                normalizedInstitution,
                normalizedHash,
                normalizedHashVersion,
                issuedAt,
                expiresAt
            );
        } catch (Exception ex) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "institutional_session_unavailable",
                ex
            );
        }
    }

    /**
     * Issues the provider-neutral credential used by OIDC and future VC flows.
     * The Marketplace service credential is the trust boundary for the
     * already-validated external identity; this token carries only normalized
     * identity metadata and an evidence hash, never the raw external token.
     */
    public IssuedCredential issueIdentity(
        String institutionId,
        String stableUserId,
        String stableUserIdMode,
        String identityProtocol,
        String identityProvider,
        String identityIssuer,
        String identitySubject,
        String identityEvidenceHash,
        String identityEvidenceHashVersion
    ) {
        String normalizedStableUserId = requireText(PucNormalizer.normalize(stableUserId), "stableUserId");
        String normalizedInstitution = requireText(institutionId, "institutionId").toLowerCase(Locale.ROOT);
        String normalizedProtocol = requireText(identityProtocol, "identityProtocol").toLowerCase(Locale.ROOT);
        if (!SUPPORTED_IDENTITY_PROTOCOLS.contains(normalizedProtocol)) {
            throw new IllegalArgumentException("Unsupported identity protocol");
        }
        String normalizedProvider = requireText(identityProvider, "identityProvider").toLowerCase(Locale.ROOT);
        String normalizedIssuer = requireText(identityIssuer, "identityIssuer");
        String normalizedSubject = requireText(identitySubject, "identitySubject");
        String normalizedHash = requireHash(identityEvidenceHash);
        String normalizedHashVersion = requireIdentityHashVersion(identityEvidenceHashVersion);
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plusSeconds(Math.max(60, ttlSeconds));

        Map<String, Object> claims = new HashMap<>();
        claims.put("aud", backendUrlResolver.resolveBaseDomain());
        claims.put("sub", SUBJECT);
        claims.put("sessionType", IDENTITY_TOKEN_TYPE);
        claims.put("institutionId", normalizedInstitution);
        claims.put("pucCiphertext", payloadCipher.encrypt(normalizedStableUserId));
        claims.put("stableUserIdMode", stableUserIdMode == null ? "" : stableUserIdMode);
        claims.put("identityProtocol", normalizedProtocol);
        claims.put("identityProvider", normalizedProvider);
        claims.put("identityIssuer", normalizedIssuer);
        claims.put("identitySubject", normalizedSubject);
        claims.put("identityEvidenceHash", normalizedHash);
        claims.put("identityEvidenceHashVersion", normalizedHashVersion);
        // The Diamond ABI still names this bytes32 field assertionHash. Keep
        // the physical alias at the contract boundary until the ABI migrates.
        claims.put("samlAssertionHash", normalizedHash);
        claims.put("samlAssertionHashVersion", normalizedHashVersion);
        claims.put("reauthenticationAt", expiresAt.getEpochSecond());
        claims.put("exp", Date.from(expiresAt));

        try {
            String token = jwtService.generateToken(claims, null);
            return new IssuedCredential(
                token,
                normalizedStableUserId,
                normalizedInstitution,
                normalizedHash,
                normalizedHashVersion,
                issuedAt,
                expiresAt,
                normalizedProtocol,
                normalizedProvider,
                normalizedIssuer,
                normalizedSubject,
                normalizedHash,
                normalizedHashVersion
            );
        } catch (Exception ex) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "institutional_session_unavailable",
                ex
            );
        }
    }

    public Credential validate(String token) {
        if (token == null || token.isBlank()) {
            throw invalid("missing_institutional_session");
        }
        String validationStage = "jwt";
        String validationCheck = "extract";
        try {
            Claims claims = (Claims) jwtService.extractAllClaims(token);
            validationStage = "claims";
            validationCheck = "session-type";
            String sessionType = claims.get("sessionType", String.class);
            if (!TOKEN_TYPE.equals(sessionType) && !IDENTITY_TOKEN_TYPE.equals(sessionType)) {
                throw new IllegalArgumentException("Invalid institutional session type");
            }
            validationCheck = "subject";
            if (!SUBJECT.equals(claims.getSubject())) {
                throw new IllegalArgumentException("Invalid institutional session subject");
            }
            validationCheck = "audience";
            String audience = normalizeAudienceClaim(claims.get("aud"));
            if (audience == null || !backendUrlResolver.resolveBaseDomain().equals(audience)) {
                throw new IllegalArgumentException("Invalid institutional session audience");
            }
            validationCheck = "institution-id";
            String institutionId = requireText(claims.get("institutionId", String.class), "institutionId");
            validationCheck = "puc-ciphertext";
            String encryptedPuc = requireText(claims.get("pucCiphertext", String.class), "PUC");
            validationStage = "puc-decryption";
            validationCheck = "decrypt";
            String puc = requireText(PucNormalizer.normalize(payloadCipher.decrypt(encryptedPuc)), "PUC");
            validationStage = "claims";
            validationCheck = "identity-evidence-hash";
            String assertionHash = IDENTITY_TOKEN_TYPE.equals(sessionType)
                ? requireHash(claims.get("identityEvidenceHash", String.class))
                : requireHash(claims.get("samlAssertionHash", String.class));
            validationCheck = "identity-evidence-hash-version";
            String assertionHashVersion = IDENTITY_TOKEN_TYPE.equals(sessionType)
                ? requireIdentityHashVersion(claims.get("identityEvidenceHashVersion", String.class))
                : requireHashVersion(claims.get("samlAssertionHashVersion", String.class));
            String identityProtocol = IDENTITY_TOKEN_TYPE.equals(sessionType)
                ? requireText(claims.get("identityProtocol", String.class), "identityProtocol")
                : "saml2";
            String identityProvider = IDENTITY_TOKEN_TYPE.equals(sessionType)
                ? requireText(claims.get("identityProvider", String.class), "identityProvider")
                : "edugain";
            String identityIssuer = IDENTITY_TOKEN_TYPE.equals(sessionType)
                ? requireText(claims.get("identityIssuer", String.class), "identityIssuer")
                : null;
            String identitySubject = IDENTITY_TOKEN_TYPE.equals(sessionType)
                ? requireText(claims.get("identitySubject", String.class), "identitySubject")
                : null;
            validationStage = "timestamps";
            validationCheck = "issued-at";
            Instant issuedAt = instantClaim(claims.getIssuedAt(), "iat");
            validationCheck = "expiration";
            Instant expiresAt = instantClaim(claims.getExpiration(), "exp");
            validationCheck = "reauthentication-at";
            Instant reauthenticationAt = instantClaim(claims.get("reauthenticationAt"), "reauthenticationAt");
            validationCheck = "token-id";
            String tokenId = requireText(claims.getId(), "jti");
            validationCheck = "session-horizon";
            if (expiresAt.getEpochSecond() != reauthenticationAt.getEpochSecond()
                || expiresAt.getEpochSecond() - issuedAt.getEpochSecond() > Math.max(60, ttlSeconds) + 60
                || !expiresAt.isAfter(Instant.now())) {
                throw new IllegalArgumentException("Institutional session is expired");
            }
            return new Credential(
                puc,
                institutionId.toLowerCase(Locale.ROOT),
                claims.get("stableUserIdMode", String.class),
                assertionHash,
                assertionHashVersion,
                issuedAt,
                reauthenticationAt,
                expiresAt,
                tokenId,
                identityProtocol,
                identityProvider,
                identityIssuer,
                identitySubject,
                assertionHash,
                assertionHashVersion
            );
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            Throwable rootCause = rootCause(ex);
            log.warn(
                "Institutional session validation failed. stage={} check={} exceptionType={} rootCauseType={}",
                validationStage,
                validationCheck,
                ex.getClass().getSimpleName(),
                rootCause.getClass().getSimpleName()
            );
            throw invalid("invalid_institutional_session");
        }
    }

    private Throwable rootCause(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }

    private String normalizeAudienceClaim(Object audienceClaim) {
        if (audienceClaim instanceof String audience) {
            return audience;
        }
        if (audienceClaim instanceof Collection<?> audiences && audiences.size() == 1) {
            Object onlyAudience = audiences.iterator().next();
            return onlyAudience instanceof String audience ? audience : null;
        }
        return null;
    }

    private Instant instantClaim(Object value, String name) {
        if (value instanceof Date date) return date.toInstant();
        if (value instanceof Number number) return Instant.ofEpochSecond(number.longValue());
        if (value instanceof String text && !text.isBlank()) return Instant.parse(text);
        throw new IllegalArgumentException("Missing " + name);
    }

    private String requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing " + name);
        return value.trim();
    }

    private String requireHash(String value) {
        String normalized = requireText(value, "samlAssertionHash");
        if (!normalized.matches("(?i)^0x[0-9a-f]{64}$")) {
            throw new IllegalArgumentException("Invalid samlAssertionHash");
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    private String requireHashVersion(String value) {
        String normalized = requireText(value, "samlAssertionHashVersion");
        if (!SUPPORTED_ASSERTION_HASH_VERSION.equals(normalized)) {
            throw new IllegalArgumentException("Unsupported samlAssertionHashVersion");
        }
        return normalized;
    }

    private String requireIdentityHashVersion(String value) {
        String normalized = requireText(value, "identityEvidenceHashVersion");
        if (!SUPPORTED_IDENTITY_HASH_VERSIONS.contains(normalized)) {
            throw new IllegalArgumentException("Unsupported identity evidence hash version");
        }
        return normalized;
    }

    private ResponseStatusException invalid(String reason) {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, reason);
    }

    public record IssuedCredential(
        String token,
        String puc,
        String institutionId,
        String samlAssertionHash,
        String samlAssertionHashVersion,
        Instant issuedAt,
        Instant expiresAt,
        String identityProtocol,
        String identityProvider,
        String identityIssuer,
        String identitySubject,
        String identityEvidenceHash,
        String identityEvidenceHashVersion
    ) {
        public IssuedCredential(
            String token,
            String puc,
            String institutionId,
            String samlAssertionHash,
            String samlAssertionHashVersion,
            Instant issuedAt,
            Instant expiresAt
        ) {
            this(
                token,
                puc,
                institutionId,
                samlAssertionHash,
                samlAssertionHashVersion,
                issuedAt,
                expiresAt,
                "saml2",
                "edugain",
                null,
                null,
                samlAssertionHash,
                samlAssertionHashVersion
            );
        }
    }

    public record Credential(
        String puc,
        String institutionId,
        String stableUserIdMode,
        String samlAssertionHash,
        String samlAssertionHashVersion,
        Instant issuedAt,
        Instant reauthenticationAt,
        Instant expiresAt,
        String tokenId,
        String identityProtocol,
        String identityProvider,
        String identityIssuer,
        String identitySubject,
        String identityEvidenceHash,
        String identityEvidenceHashVersion
    ) {
        public Credential(
            String puc,
            String institutionId,
            String stableUserIdMode,
            String samlAssertionHash,
            String samlAssertionHashVersion,
            Instant issuedAt,
            Instant reauthenticationAt,
            Instant expiresAt,
            String tokenId
        ) {
            this(
                puc,
                institutionId,
                stableUserIdMode,
                samlAssertionHash,
                samlAssertionHashVersion,
                issuedAt,
                reauthenticationAt,
                expiresAt,
                tokenId,
                "saml2",
                "edugain",
                null,
                null,
                samlAssertionHash,
                samlAssertionHashVersion
            );
        }
    }
}
