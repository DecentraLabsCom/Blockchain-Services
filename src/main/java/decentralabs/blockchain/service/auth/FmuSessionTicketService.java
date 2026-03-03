package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueResponse;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemResponse;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class FmuSessionTicketService {

    private final JwtService jwtService;
    private final SecureRandom random = new SecureRandom();
    private final ConcurrentMap<String, TicketRecord> tickets = new ConcurrentHashMap<>();

    @Value("${auth.fmu.session-ticket.ttl-seconds:120}")
    private long defaultTtlSeconds = 120;

    @Value("${auth.fmu.session-ticket.max-ttl-seconds:300}")
    private long maxTtlSeconds = 300;

    public FmuSessionTicketService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

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

        long ttl = defaultTtlSeconds;
        if (request != null && request.getTtlSeconds() != null) {
            ttl = Math.max(1, Math.min(maxTtlSeconds, request.getTtlSeconds()));
        }
        long ticketExpiry = Math.min(exp, now + ttl);
        if (ticketExpiry <= now) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_EXPIRED", "Reservation window expired");
        }

        String ticket = generateTicket();
        tickets.put(ticket, new TicketRecord(claims, ticketExpiry));

        FmuSessionTicketIssueResponse response = new FmuSessionTicketIssueResponse();
        response.setSessionTicket(ticket);
        response.setExpiresAt(ticketExpiry);
        response.setLabId(claimLabId);
        response.setReservationKey(claimReservationKey);
        response.setOneTimeUse(true);
        return response;
    }

    public FmuSessionTicketRedeemResponse redeem(FmuSessionTicketRedeemRequest request) {
        cleanupExpired();
        if (request == null || request.getSessionTicket() == null || request.getSessionTicket().isBlank()) {
            throw new SessionTicketException(HttpStatus.BAD_REQUEST, "SESSION_TICKET_INVALID", "Missing sessionTicket");
        }
        String ticket = request.getSessionTicket().trim();
        TicketRecord record = tickets.get(ticket);
        if (record == null) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_TICKET_INVALID", "Invalid session ticket");
        }

        long now = Instant.now().getEpochSecond();
        if (now >= record.expiresAt()) {
            tickets.remove(ticket);
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_TICKET_EXPIRED", "Session ticket expired");
        }
        if (!record.used().compareAndSet(false, true)) {
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "SESSION_TICKET_ALREADY_USED", "Session ticket already used");
        }

        Map<String, Object> claims = record.claims();
        String claimLabId = normalize(claims.get("labId"));
        String claimReservationKey = normalize(claims.get("reservationKey"));
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

    private void cleanupExpired() {
        long now = Instant.now().getEpochSecond();
        tickets.entrySet().removeIf(entry -> now >= entry.getValue().expiresAt());
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
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Invalid booking token");
        }
    }

    private void enforceFmuClaims(Map<String, Object> claims) {
        String resourceType = normalize(claims.get("resourceType"));
        if (!"fmu".equalsIgnoreCase(resourceType)) {
            throw new SessionTicketException(HttpStatus.FORBIDDEN, "FORBIDDEN", "Booking token is not authorized for FMU");
        }
        if (normalize(claims.get("labId")) == null || normalize(claims.get("accessKey")) == null) {
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
            throw new SessionTicketException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", message);
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

    private record TicketRecord(Map<String, Object> claims, long expiresAt, AtomicBoolean used) {
        TicketRecord(Map<String, Object> claims, long expiresAt) {
            this(claims, expiresAt, new AtomicBoolean(false));
        }
    }
}
