package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AccessCredentialSessionObservedRequest;
import decentralabs.blockchain.service.auth.SessionStartedAttestationSigner.SessionStartedAttestationPayload;
import decentralabs.blockchain.service.auth.SessionStartedAttestationSigner.SignedSessionStartedAttestation;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.LogSanitizer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Credentials;

@Service
@Slf4j
public class SessionStartedAttestationService {

    private final JdbcTemplate jdbcTemplate;
    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final SessionStartedAttestationSigner signer;

    public SessionStartedAttestationService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        InstitutionalWalletService institutionalWalletService,
        WalletService walletService,
        SessionStartedAttestationSigner signer
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.institutionalWalletService = institutionalWalletService;
        this.walletService = walletService;
        this.signer = signer;
    }

    public boolean recordSessionStarted(
        AccessCredentialSessionObservedRequest request,
        long startedAt,
        String accessType
    ) {
        if (jdbcTemplate == null) {
            log.debug("SessionStarted attestation skipped: no datasource configured");
            return false;
        }
        if (request == null || !hasText(request.getReservationKey())) {
            return false;
        }
        if (!hasText(request.getSessionId())) {
            log.debug("SessionStarted attestation skipped: missing sessionId");
            return false;
        }
        if (!hasCredentialReference(request)) {
            return false;
        }

        try {
            AuditCredential credential = findMatchingCredential(request);
            if (credential == null) {
                log.debug("SessionStarted attestation skipped: no issued credential found for reservation");
                return false;
            }

            Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
            String signerAddress = credentials.getAddress();
            if (!isProviderSignerForLab(signerAddress, credential.labId())) {
                log.warn(
                    "SessionStarted attestation skipped: signer {} is not the on-chain provider for lab {}",
                    LogSanitizer.maskIdentifier(signerAddress),
                    LogSanitizer.sanitize(credential.labId())
                );
                return false;
            }
            String normalizedAccessType = normalizeAccessType(firstNonBlank(accessType, credential.accessType()));
            String nonce = buildNonce(
                credential.reservationKey(),
                request.getGatewayId(),
                request.getSessionId(),
                normalizedAccessType,
                startedAt,
                credential.credentialHash()
            );
            SessionStartedAttestationPayload payload = new SessionStartedAttestationPayload(
                signerAddress,
                credential.reservationKey(),
                credential.labId(),
                credential.pucHash(),
                request.getGatewayId(),
                request.getSessionId(),
                normalizedAccessType,
                startedAt,
                nonce,
                credential.credentialHash(),
                request.getClientProofHash()
            );
            SignedSessionStartedAttestation signed = signer.sign(payload, credentials);
            return persist(payload, signed, request);
        } catch (BadSqlGrammarException ex) {
            log.warn("SessionStarted attestation table unavailable: {}", LogSanitizer.sanitize(ex.getMessage()));
        } catch (DataAccessException ex) {
            log.warn("SessionStarted attestation write failed: {}", LogSanitizer.sanitize(ex.getMessage()));
        } catch (RuntimeException ex) {
            log.warn("SessionStarted attestation signing failed: {}", LogSanitizer.sanitize(ex.getMessage()));
        }
        return false;
    }

    public List<SessionStartedAttestationEntry> findByReservationKey(String reservationKey) {
        if (jdbcTemplate == null || !hasText(reservationKey)) {
            return List.of();
        }
        try {
            return jdbcTemplate.query(
                """
                SELECT reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                       session_id, access_type, started_at, nonce, credential_hash,
                       client_proof_hash, digest, signature, credential_reference_type,
                       credential_reference_id
                FROM session_started_attestations
                WHERE reservation_key = ?
                ORDER BY started_at ASC, id ASC
                """,
                attestationEntryRowMapper(),
                reservationKey
            );
        } catch (BadSqlGrammarException ex) {
            log.warn("SessionStarted attestation table unavailable for lookup: {}", LogSanitizer.sanitize(ex.getMessage()));
        } catch (DataAccessException ex) {
            log.warn("SessionStarted attestation lookup failed: {}", LogSanitizer.sanitize(ex.getMessage()));
        }
        return List.of();
    }

    private AuditCredential findMatchingCredential(AccessCredentialSessionObservedRequest request) {
        List<AuditCredential> credentials = jdbcTemplate.query(
            """
            SELECT reservation_key, lab_id, puc_hash, access_type, jwt_jti,
                   fmu_ticket_id, credential_hash
            FROM access_credential_audit
            WHERE reservation_key = ?
              AND (
                (? IS NOT NULL AND credential_hash = ?)
                OR (? IS NOT NULL AND jwt_jti = ?)
                OR (? IS NOT NULL AND fmu_ticket_id = ?)
              )
            ORDER BY updated_at DESC, id DESC
            LIMIT 1
            """,
            auditCredentialRowMapper(),
            request.getReservationKey(),
            blankToNull(request.getCredentialHash()),
            blankToNull(request.getCredentialHash()),
            blankToNull(request.getJwtJti()),
            blankToNull(request.getJwtJti()),
            blankToNull(request.getFmuTicketId()),
            blankToNull(request.getFmuTicketId())
        );
        return credentials.isEmpty() ? null : credentials.getFirst();
    }

    private boolean persist(
        SessionStartedAttestationPayload payload,
        SignedSessionStartedAttestation signed,
        AccessCredentialSessionObservedRequest request
    ) {
        int updated = jdbcTemplate.update(
            """
            INSERT INTO session_started_attestations (
                reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                session_id, access_type, started_at, nonce, credential_hash,
                client_proof_hash, digest, signature, credential_reference_type,
                credential_reference_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                updated_at = CURRENT_TIMESTAMP
            """,
            payload.reservationKey(),
            payload.labId(),
            payload.pucHash(),
            payload.signer(),
            payload.gatewayId(),
            payload.sessionId(),
            payload.accessType(),
            toTimestamp(payload.startedAt()),
            payload.nonce(),
            payload.credentialHash(),
            blankToNull(payload.clientProofHash()),
            signed.digest(),
            signed.signature(),
            credentialReferenceType(request),
            credentialReferenceId(request)
        );
        return updated > 0;
    }

    private RowMapper<AuditCredential> auditCredentialRowMapper() {
        return (rs, rowNum) -> new AuditCredential(
            rs.getString("reservation_key"),
            rs.getString("lab_id"),
            rs.getString("puc_hash"),
            rs.getString("access_type"),
            rs.getString("jwt_jti"),
            rs.getString("fmu_ticket_id"),
            rs.getString("credential_hash")
        );
    }

    private RowMapper<SessionStartedAttestationEntry> attestationEntryRowMapper() {
        return (rs, rowNum) -> new SessionStartedAttestationEntry(
            rs.getString("reservation_key"),
            rs.getString("lab_id"),
            rs.getString("puc_hash"),
            rs.getString("signer_address"),
            rs.getString("gateway_id"),
            rs.getString("session_id"),
            rs.getString("access_type"),
            epochSecond(rs.getTimestamp("started_at")),
            rs.getString("nonce"),
            rs.getString("credential_hash"),
            rs.getString("client_proof_hash"),
            rs.getString("digest"),
            rs.getString("signature"),
            rs.getString("credential_reference_type"),
            rs.getString("credential_reference_id")
        );
    }

    private String credentialReferenceType(AccessCredentialSessionObservedRequest request) {
        if (hasText(request.getCredentialHash())) {
            return "credential_hash";
        }
        if (hasText(request.getJwtJti())) {
            return "jwt_jti";
        }
        return "fmu_ticket_id";
    }

    private String credentialReferenceId(AccessCredentialSessionObservedRequest request) {
        return firstNonBlank(
            request.getCredentialHash(),
            firstNonBlank(request.getJwtJti(), request.getFmuTicketId())
        );
    }

    private boolean hasCredentialReference(AccessCredentialSessionObservedRequest request) {
        return hasText(request.getCredentialHash())
            || hasText(request.getJwtJti())
            || hasText(request.getFmuTicketId());
    }

    private boolean isProviderSignerForLab(String signerAddress, String labId) {
        BigInteger parsedLabId = parseLabId(labId);
        if (parsedLabId == null) {
            log.warn("SessionStarted attestation skipped: cannot resolve numeric labId {}", LogSanitizer.sanitize(labId));
            return false;
        }
        return walletService.isLabOwnedByProvider(signerAddress, parsedLabId);
    }

    private BigInteger parseLabId(String labId) {
        if (!hasText(labId)) {
            return null;
        }
        String trimmed = labId.trim();
        try {
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                return new BigInteger(trimmed.substring(2), 16);
            }
            return new BigInteger(trimmed);
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private String buildNonce(
        String reservationKey,
        String gatewayId,
        String sessionId,
        String accessType,
        long startedAt,
        String credentialHash
    ) {
        return "0x" + sha256Hex(String.join("|",
            nullToEmpty(reservationKey),
            nullToEmpty(gatewayId),
            nullToEmpty(sessionId),
            nullToEmpty(accessType),
            Long.toString(startedAt),
            nullToEmpty(credentialHash)
        ));
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm not available", ex);
        }
    }

    private Timestamp toTimestamp(long epochSecond) {
        return Timestamp.from(Instant.ofEpochSecond(epochSecond));
    }

    private Long epochSecond(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant().getEpochSecond();
    }

    private String normalizeAccessType(String value) {
        return hasText(value) ? value.trim().toLowerCase(Locale.ROOT) : "session";
    }

    private String firstNonBlank(String first, String second) {
        return hasText(first) ? first : second;
    }

    private String blankToNull(String value) {
        return hasText(value) ? value.trim() : null;
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record AuditCredential(
        String reservationKey,
        String labId,
        String pucHash,
        String accessType,
        String jwtJti,
        String fmuTicketId,
        String credentialHash
    ) { }

    public record SessionStartedAttestationEntry(
        String reservationKey,
        String labId,
        String pucHash,
        String signerAddress,
        String gatewayId,
        String sessionId,
        String accessType,
        Long startedAt,
        String nonce,
        String credentialHash,
        String clientProofHash,
        String digest,
        String signature,
        String credentialReferenceType,
        String credentialReferenceId
    ) { }
}
