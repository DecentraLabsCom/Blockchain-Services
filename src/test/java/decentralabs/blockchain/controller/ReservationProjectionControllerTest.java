package decentralabs.blockchain.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.persistence.ReservationProjectionService;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class ReservationProjectionControllerTest {

    private ReservationProjectionService service;
    private ReservationProjectionController controller;

    @BeforeEach
    void setUp() {
        service = mock(ReservationProjectionService.class);
        controller = new ReservationProjectionController(service);
    }

    @Test
    void returnsOnlyTheAuthenticatedGatewayProjection() {
        var credential = new ReservationProjectionService.ProjectionCredential(
            "lite.example", "rpr-secret", "https://lite.example"
        );
        when(service.authenticate("lite.example", "rpr-secret")).thenReturn(credential);
        when(service.findReservations(
            credential,
            java.time.Instant.parse("2026-08-14T10:00:00Z"),
            java.time.Instant.parse("2026-08-14T12:00:00Z"),
            200
        )).thenReturn(List.of(new ReservationProjectionService.ReservationProjection(
            "0xreservation", "42", "2026-08-14T10:30:00Z", "2026-08-14T11:30:00Z", "CONFIRMED"
        )));

        ResponseEntity<?> response = controller.getProjection(
            "lite.example",
            "rpr-secret",
            "2026-08-14T10:00:00Z",
            "2026-08-14T12:00:00Z",
            200
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().toString()).contains("0xreservation");
    }

    @Test
    void rejectsInvalidCredentialBeforeReadingTheProjection() {
        when(service.authenticate("lite.example", "wrong")).thenReturn(null);

        ResponseEntity<?> response = controller.getProjection(
            "lite.example", "wrong", "2026-08-14T10:00:00Z", "2026-08-14T12:00:00Z", 200
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
}
