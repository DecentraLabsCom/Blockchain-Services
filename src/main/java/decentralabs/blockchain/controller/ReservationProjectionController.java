package decentralabs.blockchain.controller;

import decentralabs.blockchain.service.persistence.ReservationProjectionService;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Authenticated reservation feed consumed by Lite gateway operations workers. */
@RestController
@RequestMapping("/reservations")
@RequiredArgsConstructor
public class ReservationProjectionController {

    private static final Duration MAX_WINDOW = Duration.ofHours(48);

    private final ReservationProjectionService projectionService;

    @GetMapping("/projection")
    public ResponseEntity<?> getProjection(
        @RequestHeader(value = "X-Gateway-ID", required = false) String gatewayId,
        @RequestHeader(value = "X-Reservation-Projection-Token", required = false) String token,
        @RequestParam("from") String fromValue,
        @RequestParam("to") String toValue,
        @RequestParam(value = "limit", defaultValue = "200") int limit
    ) {
        ReservationProjectionService.ProjectionCredential credential =
            projectionService.authenticate(gatewayId, token);
        if (credential == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "code", "RESERVATION_PROJECTION_FORBIDDEN",
                "error", "Invalid reservation projection credential"
            ));
        }
        if (limit < 1 || limit > 500) {
            return ResponseEntity.badRequest().body(Map.of(
                "code", "INVALID_LIMIT",
                "error", "limit must be between 1 and 500"
            ));
        }

        Instant from;
        Instant to;
        try {
            from = Instant.parse(fromValue);
            to = Instant.parse(toValue);
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(Map.of(
                "code", "INVALID_WINDOW",
                "error", "from and to must be ISO-8601 instants"
            ));
        }
        if (from.isAfter(to) || Duration.between(from, to).compareTo(MAX_WINDOW) > 0) {
            return ResponseEntity.badRequest().body(Map.of(
                "code", "INVALID_WINDOW",
                "error", "The requested window must be ordered and no larger than 48 hours"
            ));
        }

        try {
            List<ReservationProjectionService.ReservationProjection> reservations =
                projectionService.findReservations(credential, from, to, limit);
            return ResponseEntity.ok(Map.of(
                "gatewayId", credential.gatewayId(),
                "from", from.toString(),
                "to", to.toString(),
                "reservations", reservations
            ));
        } catch (DataAccessException | IllegalStateException ex) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                "code", "RESERVATION_PROJECTION_UNAVAILABLE",
                "error", "Reservation projection is temporarily unavailable"
            ));
        }
    }
}
