package decentralabs.blockchain.service.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueResponse;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemResponse;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
public class FmuSessionTicketService {

    private static final String TICKETS_TABLE = "fmu_session_tickets";

    private final JwtService jwtService;
    private final JdbcTemplate jdbcTemplate;
    private final AccessCredentialAuditService accessCredentialAuditService;
    private final AccessCodeTokenCipher ticketCipher;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecureRandom random = new SecureRandom();
    private final ConcurrentMap<String, TicketRecord> tickets = new ConcurrentHashMap<>();

    @Value("${auth.fmu.session-ticket.max-ttl-seconds:300}")
    private long maxTtlSeconds = 300;

    @Value("${auth.fmu.session-ticket.require-persistence:true}")
    private boolean requirePersistence = true;

    public FmuSessionTicketService(
        JwtService jwtService,
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        AccessCredentialAuditService accessCredentialAuditService,
        AccessCodeTokenCipher ticketCipher
    ) {
        this.jwtService = jwtService;
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.accessCredentialAuditService = accessCredentialAuditService;
        this.ticketCipher = ticketCipher;
    }

    @Transactional
    public FmuSessionTicketIssueResponse issue(String bearerToken, FmuSessionTicketIssueRequest request) {
        cleanupExpired();
        String token = normalizeBearerToken(bearerToken);
        Map<String, Object> claims = extractClaims(token);
        enforceFmuClaims(claims);

        long now = Instant.now().getEpochSecond();
        long nbf = toEpochSecond(claims.get("nbf"), "Missing nbf claim");
        long exp = toEpochSecond(claims.get("exp"), "Missing exp claim");
        if (now < nbf) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "RESERVATION_NOT_ACTIVE", "Reservation is not active yet");
        }
        if (now >= exp) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_EXPIRED", "Reservation window expired");
        }

        String claimLabId = normalize(claims.get("labId"));
        String claimReservationKey = normalize(claims.get("reservationKey"));
        if (request != null && request.getLabId() != null && !request.getLabId().isBlank() && !Objects.equals(request.getLabId().trim(), claimLabId)) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "LAB_MISMATCH", "Ticket request labId does not match booking token");
        }
        if (request != null && request.getReservationKey() != null && !request.getReservationKey().isBlank()
            && !request.getReservationKey().trim().equalsIgnoreCase(claimReservationKey)) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "FORBIDDEN", "Ticket request reservationKey does not match booking token");
        }

        // Ticket is reusable within the reservation window — expire with the booking, not a short TTL.
        // If caller explicitly requests a shorter TTL (e.g. for a one-off embed), honour it.
        long ticketExpiry = exp;
        if (request != null && request.getTtlSeconds() != null) {
            long ttl = Math.max(1, Math.min(maxTtlSeconds, request.getTtlSeconds()));
            ticketExpiry = Math.min(exp, now + ttl);
        }
        if (ticketExpiry <= now) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_EXPIRED", "Reservation window expired");
        }

        String ticket = generateTicket();
        TicketRecord record = new TicketRecord(claims, ticketExpiry);
        persistTicket(ticket, record);
        try {
            accessCredentialAuditService.recordFmuTicketIssuedRequired(ticket, claims, ticketExpiry);
        } catch (RuntimeException auditFailure) {
            discardTicketAfterAuditFailure(ticket, auditFailure);
            throw auditFailure;
        }

        FmuSessionTicketIssueResponse response = new FmuSessionTicketIssueResponse();
        response.setSessionTicket(ticket);
        response.setExpiresAt(ticketExpiry);
        response.setLabId(claimLabId);
        response.setReservationKey(claimReservationKey);
        response.setOneTimeUse(false);
        return response;
    }

    public FmuSessionTicketRedeemResponse redeem(
        FmuSessionTicketRedeemRequest request,
        String authenticatedGatewayId
    ) {
        cleanupExpired();
        String gatewayId = normalize(authenticatedGatewayId);
        if (gatewayId == null) {
            throw new SessionTicketException(
                HttpStatus.UNAUTHORIZED,
                "UNAUTHORIZED",
                "Missing authenticated gateway identity"
            );
        }
        if (request == null || request.getSessionTicket() == null || request.getSessionTicket().isBlank()) {
            throw new SessionTicketException(HttpStatus.BAD_REQUEST, "SESSION_TICKET_INVALID", "Missing sessionTicket");
        }
        String ticket = request.getSessionTicket().trim();
        TicketRecord record = loadTicket(ticket);
        if (record == null) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_TICKET_INVALID", "Invalid session ticket");
        }

        long now = Instant.now().getEpochSecond();
        if (now >= record.expiresAt()) {
            removeTicket(ticket);
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_TICKET_EXPIRED", "Session ticket expired");
        }

        Map<String, Object> claims = record.claims();
        String claimLabId = normalize(claims.get("labId"));
        String claimReservationKey = normalize(claims.get("reservationKey"));
        String targetGatewayId = normalize(claims.get("targetGatewayId"));
        if (targetGatewayId == null || !gatewayId.equalsIgnoreCase(targetGatewayId)) {
            throw new SessionTicketException(
                HttpStatus.FORBIDDEN,
                "GATEWAY_ID_MISMATCH",
                "Session ticket is not authorized for this gateway"
            );
        }
        if (request.getLabId() != null && !request.getLabId().isBlank() && !request.getLabId().trim().equals(claimLabId)) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "LAB_MISMATCH", "Ticket labId mismatch");
        }
        if (request.getReservationKey() != null && !request.getReservationKey().isBlank()
            && !request.getReservationKey().trim().equalsIgnoreCase(claimReservationKey)) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "FORBIDDEN", "Ticket reservationKey mismatch");
        }

        long nbf = toEpochSecond(claims.get("nbf"), "Missing nbf claim");
        long exp = toEpochSecond(claims.get("exp"), "Missing exp claim");
        if (now < nbf) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "RESERVATION_NOT_ACTIVE", "Reservation is not active yet");
        }
        if (now >= exp) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_EXPIRED", "Reservation window expired");
        }

        FmuSessionTicketRedeemResponse response = new FmuSessionTicketRedeemResponse();
        response.setClaims(claims);
        response.setExpiresAt(Math.min(record.expiresAt(), exp));
        return response;
    }

    @Scheduled(fixedDelayString = "${auth.fmu.session-ticket.cleanup-interval-ms:60000}")
    public void scheduledCleanupExpired() {
        cleanupExpired();
    }

    private void cleanupExpired() {
        long now = Instant.now().getEpochSecond();
        tickets.entrySet().removeIf(entry -> now >= entry.getValue().expiresAt());
        cleanupPersisted(now);
    }

    private void persistTicket(String ticket, TicketRecord record) {
        if (!isPersistentStoreAvailable()) {
            if (requirePersistence) {
                throw persistenceUnavailable("FMU session ticket persistence is required but no database is configured");
            }
            tickets.put(ticketHash(ticket), record);
            return;
        }
        try {
            jdbcTemplate.update(
                """
                INSERT INTO fmu_session_tickets (ticket_hash, lab_id, reservation_key, encrypted_claims, expires_at)
                VALUES (?, ?, ?, ?, FROM_UNIXTIME(?))
                """,
                ticketHash(ticket),
                normalize(record.claims().get("labId")),
                normalize(record.claims().get("reservationKey")),
                ticketCipher.encrypt(objectMapper.writeValueAsString(record.claims())),
                record.expiresAt()
            );
        } catch (JsonProcessingException e) {
            throw new SessionTicketException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "SESSION_TICKET_PERSISTENCE_ERROR",
                "Failed to serialize session ticket claims",
                e
            );
        } catch (DataAccessException e) {
            handlePersistenceException("persist", e);
        } catch (IllegalStateException e) {
            throw persistenceUnavailable("Failed to encrypt persisted FMU session ticket", e);
        }
    }

    private TicketRecord loadTicket(String ticket) {
        if (isPersistentStoreAvailable()) {
            return loadTicketFromPersistence(ticket);
        }
        if (requirePersistence) {
            throw persistenceUnavailable("FMU session ticket persistence is required but no database is configured");
        }
        return tickets.get(ticketHash(ticket));
    }

    private TicketRecord loadTicketFromPersistence(String ticket) {
        if (!isPersistentStoreAvailable()) {
            return null;
        }
        try {
            return jdbcTemplate.query(
                """
                SELECT encrypted_claims, UNIX_TIMESTAMP(expires_at)
                FROM fmu_session_tickets
                WHERE ticket_hash = ?
                LIMIT 1
                """,
                ps -> ps.setString(1, ticketHash(ticket)),
                rs -> {
                    if (!rs.next()) {
                        return null;
                    }
                    Map<String, Object> claims;
                    try {
                        claims = objectMapper.readValue(
                            ticketCipher.decrypt(rs.getString(1)),
                            new TypeReference<Map<String, Object>>() { }
                        );
                    } catch (JsonProcessingException e) {
                        throw new IllegalStateException("Failed to deserialize persisted session ticket", e);
                    }
                    long expiresAt = rs.getLong(2);
                    return new TicketRecord(claims, expiresAt);
                }
            );
        } catch (DataAccessException e) {
            handlePersistenceException("load", e);
            return null;
        } catch (IllegalStateException e) {
            throw persistenceUnavailable("Failed to decrypt persisted FMU session ticket", e);
        }
    }

    private void removeTicket(String ticket) {
        tickets.remove(ticketHash(ticket));
        if (!isPersistentStoreAvailable()) {
            return;
        }
        try {
            jdbcTemplate.update("DELETE FROM " + TICKETS_TABLE + " WHERE ticket_hash = ?", ticketHash(ticket));
        } catch (DataAccessException e) {
            handlePersistenceException("delete", e);
        }
    }

    private void cleanupPersisted(long now) {
        if (!isPersistentStoreAvailable()) {
            return;
        }
        try {
            jdbcTemplate.update(
                "DELETE FROM " + TICKETS_TABLE + " WHERE expires_at <= FROM_UNIXTIME(?)",
                now
            );
        } catch (DataAccessException e) {
            handlePersistenceException("cleanup", e);
        }
    }

    private boolean isPersistentStoreAvailable() {
        return jdbcTemplate != null;
    }

    private void discardTicketAfterAuditFailure(String ticket, RuntimeException auditFailure) {
        tickets.remove(ticketHash(ticket));
        if (!isPersistentStoreAvailable()) {
            return;
        }
        try {
            jdbcTemplate.update("DELETE FROM " + TICKETS_TABLE + " WHERE ticket_hash = ?", ticketHash(ticket));
        } catch (DataAccessException cleanupFailure) {
            log.error("Failed to discard FMU session ticket after audit failure", cleanupFailure);
            auditFailure.addSuppressed(cleanupFailure);
        }
    }

    private void handlePersistenceException(String operation, DataAccessException ex) {
        throw persistenceUnavailable("FMU session ticket persistence failed during " + operation, ex);
    }

    private String normalizeBearerToken(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Missing bearer token");
        }
        String trimmed = bearerToken.trim();
        if (!trimmed.startsWith("Bearer ")) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Invalid Authorization header");
        }
        return trimmed.substring("Bearer ".length()).trim();
    }

    private Map<String, Object> extractClaims(String token) {
        if (!jwtService.validateToken(token)) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Invalid booking token");
        }
        try {
            return jwtService.extractAllClaims(token);
        } catch (RuntimeException e) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Invalid booking token", e);
        }
    }

    private void enforceFmuClaims(Map<String, Object> claims) {
        String resourceType = normalize(claims.get("resourceType"));
        if (!"fmu".equalsIgnoreCase(resourceType)) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "FORBIDDEN", "Booking token is not authorized for FMU");
        }
        if (normalize(claims.get("labId")) == null
            || normalize(claims.get("accessKey")) == null
            || normalize(claims.get("reservationKey")) == null
            || normalize(claims.get("targetGatewayId")) == null) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "FORBIDDEN", "Booking token is missing FMU claims");
        }
    }

    private long toEpochSecond(Object value, String message) {
        if (value == null) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", message);
        }
        if (value instanceof Integer v) {
            return v.longValue();
        }
        if (value instanceof Long v) {
            return v;
        }
        if (value instanceof BigInteger v) {
            return v.longValue();
        }
        if (value instanceof Number v) {
            return v.longValue();
        }
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException e) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", message, e);
        }
    }

    private String normalize(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private String generateTicket() {
        byte[] bytes = new byte[18];
        random.nextBytes(bytes);
        return "st_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String ticketHash(String ticket) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(ticket.getBytes(StandardCharsets.UTF_8));
            StringBuilder value = new StringBuilder(hash.length * 2);
            for (byte current : hash) {
                value.append(String.format("%02x", current));
            }
            return value.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm not available", ex);
        }
    }

    private SessionTicketException persistenceUnavailable(String message) {
        return persistenceUnavailable(message, null);
    }

    private SessionTicketException persistenceUnavailable(String message, Throwable cause) {
        if (cause == null) {
            log.error(message);
        } else {
            log.error(message, cause);
        }
        return new SessionTicketException(
            HttpStatus.SERVICE_UNAVAILABLE,
            "SESSION_TICKET_PERSISTENCE_UNAVAILABLE",
            message,
            cause
        );
    }

    private record TicketRecord(Map<String, Object> claims, long expiresAt) {}
}
