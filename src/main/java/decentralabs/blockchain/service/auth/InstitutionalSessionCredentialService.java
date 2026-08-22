package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.intent.IntentPayloadCipher;
import decentralabs.blockchain.util.PucNormalizer;
import io.jsonwebtoken.Claims;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Backend-owned credential used after the initial fresh SAML validation. */
@Service
@RequiredArgsConstructor
public class InstitutionalSessionCredentialService {

    private static final String TOKEN_TYPE = "institutional_saml_session";
    private static final String SUBJECT = "institutional-session";
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
        String samlAssertionHash
    ) {
        String normalizedPuc = requireText(PucNormalizer.normalize(puc), "PUC");
        String normalizedInstitution = requireText(institutionId, "institutionId").toLowerCase(Locale.ROOT);
        String normalizedHash = requireHash(samlAssertionHash);
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
            "reauthenticationAt", expiresAt.getEpochSecond(),
            "exp", Date.from(expiresAt)
        );

        try {
            String token = jwtService.generateToken(claims, null);
            return new IssuedCredential(token, normalizedPuc, normalizedInstitution, normalizedHash, issuedAt, expiresAt);
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
            if (!TOKEN_TYPE.equals(claims.get("sessionType", String.class))) {
                throw new IllegalArgumentException("Invalid institutional session type");
            }
            validationCheck = "subject";
            if (!SUBJECT.equals(claims.getSubject())) {
                throw new IllegalArgumentException("Invalid institutional session subject");
            }
            validationCheck = "audience";
            Object audience = claims.get("aud");
            if (audience == null || !backendUrlResolver.resolveBaseDomain().equals(String.valueOf(audience))) {
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
            validationCheck = "saml-assertion-hash";
            String assertionHash = requireHash(claims.get("samlAssertionHash", String.class));
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
                issuedAt,
                reauthenticationAt,
                expiresAt,
                tokenId
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

    private ResponseStatusException invalid(String reason) {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, reason);
    }

    public record IssuedCredential(
        String token,
        String puc,
        String institutionId,
        String samlAssertionHash,
        Instant issuedAt,
        Instant expiresAt
    ) {}

    public record Credential(
        String puc,
        String institutionId,
        String stableUserIdMode,
        String samlAssertionHash,
        Instant issuedAt,
        Instant reauthenticationAt,
        Instant expiresAt,
        String tokenId
    ) {}
}
