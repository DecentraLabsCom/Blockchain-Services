package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.FmuSessionTicketIssueRequest;
import decentralabs.blockchain.dto.auth.FmuSessionTicketRedeemRequest;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class FmuSessionTicketServiceTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private JdbcTemplate jdbcTemplate;

    private FmuSessionTicketService service;

    @BeforeEach
    void setUp() {
        service = buildService(null);
    }

    @Test
    void shouldIssueAndRedeemTicketOnceWithoutDatabase() {
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
    void shouldPersistTicketWhenDatabaseIsAvailable() {
        service = buildService(jdbcTemplate);

        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = validClaims(now);
        when(jwtService.validateToken("booking-token")).thenReturn(true);
        when(jwtService.extractAllClaims("booking-token")).thenReturn(claims);

        FmuSessionTicketIssueRequest issueRequest = new FmuSessionTicketIssueRequest();
        issueRequest.setLabId("42");
        issueRequest.setReservationKey("0xabc");

        var issueResponse = service.issue("Bearer booking-token", issueRequest);

        assertThat(issueResponse.getSessionTicket()).startsWith("st_");
        org.mockito.Mockito.verify(jdbcTemplate).update(
            org.mockito.ArgumentMatchers.contains("INSERT INTO fmu_session_tickets"),
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            anyLong()
        );
    }

    @Test
    void shouldRedeemPersistedTicketOnce() throws Exception {
        service = buildService(jdbcTemplate);

        long now = System.currentTimeMillis() / 1000;
        when(jdbcTemplate.update(org.mockito.ArgumentMatchers.contains("DELETE FROM fmu_session_tickets WHERE expires_at"), anyLong())).thenReturn(0);
        when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
            .thenAnswer(invocation -> {
                @SuppressWarnings("unchecked")
                ResultSetExtractor<Object> extractor = invocation.getArgument(2, ResultSetExtractor.class);
                ResultSet resultSet = org.mockito.Mockito.mock(ResultSet.class);
                when(resultSet.next()).thenReturn(true);
                when(resultSet.getString(1)).thenReturn("""
                    {"sub":"user-1","labId":42,"accessKey":"test.fmu","resourceType":"fmu","reservationKey":"0xabc","nbf":%d,"exp":%d}
                    """.formatted(now - 30, now + 300).trim());
                when(resultSet.getLong(2)).thenReturn(now + 120);
                when(resultSet.getTimestamp(3)).thenReturn(null);
                return extractor.extractData(resultSet);
            });
        when(jdbcTemplate.update(org.mockito.ArgumentMatchers.contains("UPDATE fmu_session_tickets"), anyString())).thenReturn(1).thenReturn(0);

        FmuSessionTicketRedeemRequest redeemRequest = new FmuSessionTicketRedeemRequest();
        redeemRequest.setSessionTicket("st_test");
        redeemRequest.setLabId("42");
        redeemRequest.setReservationKey("0xabc");

        var redeemResponse = service.redeem(redeemRequest);
        assertThat(redeemResponse.getClaims()).containsEntry("resourceType", "fmu");

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

    private FmuSessionTicketService buildService(JdbcTemplate template) {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(template);
        FmuSessionTicketService candidate = new FmuSessionTicketService(jwtService, jdbcTemplateProvider);
        ReflectionTestUtils.setField(candidate, "defaultTtlSeconds", 120L);
        ReflectionTestUtils.setField(candidate, "maxTtlSeconds", 300L);
        return candidate;
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
