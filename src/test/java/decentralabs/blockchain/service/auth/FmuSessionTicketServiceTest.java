package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemRequest;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class FmuSessionTicketServiceTest {

    @Mock
    private JwtService jwtService;

    private FmuSessionTicketService service;

    @BeforeEach
    void setUp() {
        service = new FmuSessionTicketService(jwtService);
        ReflectionTestUtils.setField(service, "defaultTtlSeconds", 120L);
        ReflectionTestUtils.setField(service, "maxTtlSeconds", 300L);
    }

    @Test
    void shouldIssueAndRedeemTicketOnce() {
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = validClaims(now);
        when(jwtService.validateToken("booking-token")).thenReturn(true);
        when(jwtService.extractAllClaims("booking-token")).thenReturn(claims);

        FmuSessionTicketIssueRequest issueRequest = new FmuSessionTicketIssueRequest();
        issueRequest.setLabId("42");
        issueRequest.setReservationKey("0xabc");
        var issueResponse = service.issue("Bearer booking-token", issueRequest);

        assertThat(issueResponse.getSessionTicket()).startsWith("st_");
        assertThat(issueResponse.getLabId()).isEqualTo("42");

        FmuSessionTicketRedeemRequest redeemRequest = new FmuSessionTicketRedeemRequest();
        redeemRequest.setSessionTicket(issueResponse.getSessionTicket());
        redeemRequest.setLabId("42");
        redeemRequest.setReservationKey("0xabc");
        var redeemResponse = service.redeem(redeemRequest);

        assertThat(redeemResponse.getClaims()).containsEntry("resourceType", "fmu");
        assertThat(redeemResponse.getClaims()).containsEntry("accessKey", "test.fmu");

        assertThatThrownBy(() -> service.redeem(redeemRequest))
            .isInstanceOf(SessionTicketException.class)
            .extracting("code")
            .isEqualTo("SESSION_TICKET_ALREADY_USED");
    }

    @Test
    void shouldRejectNonFmuToken() {
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = validClaims(now);
        claims.put("resourceType", "lab");
        when(jwtService.validateToken("booking-token")).thenReturn(true);
        when(jwtService.extractAllClaims("booking-token")).thenReturn(claims);

        assertThatThrownBy(() -> service.issue("Bearer booking-token", new FmuSessionTicketIssueRequest()))
            .isInstanceOf(SessionTicketException.class)
            .extracting("code")
            .isEqualTo("FORBIDDEN");
    }

    @Test
    void shouldRejectMissingBearerToken() {
        assertThatThrownBy(() -> service.issue(null, new FmuSessionTicketIssueRequest()))
            .isInstanceOf(SessionTicketException.class)
            .extracting("code")
            .isEqualTo("UNAUTHORIZED");
    }

    private Map<String, Object> validClaims(long now) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user-1");
        claims.put("labId", 42);
        claims.put("accessKey", "test.fmu");
        claims.put("resourceType", "fmu");
        claims.put("reservationKey", "0xabc");
        claims.put("nbf", now - 30);
        claims.put("exp", now + 300);
        return claims;
    }
}
