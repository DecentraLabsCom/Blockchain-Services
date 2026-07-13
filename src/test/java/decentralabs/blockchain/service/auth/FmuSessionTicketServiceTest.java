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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
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

    @Mock
    private AccessCredentialAuditService accessCredentialAuditService;

    private FmuSessionTicketService service;
    private AccessCodeTokenCipher ticketCipher;

    @BeforeEach
    void setUp() {
        ticketCipher = new AccessCodeTokenCipher(
            Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32])
        );
        service = buildService(null);
    }

    @Test
    void shouldIssueAndRedeemTicketMultipleTimesWithoutDatabase() {
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
        assertThat(issueResponse.isOneTimeUse()).isFalse();
        org.mockito.Mockito.verify(accessCredentialAuditService)
            .recordFmuTicketIssued(org.mockito.Mockito.eq(issueResponse.getSessionTicket()), org.mockito.Mockito.eq(claims), org.mockito.Mockito.anyLong());

        FmuSessionTicketRedeemRequest redeemRequest = new FmuSessionTicketRedeemRequest();
        redeemRequest.setSessionTicket(issueResponse.getSessionTicket());
        redeemRequest.setLabId("42");
        redeemRequest.setReservationKey("0xabc");
        var redeemResponse = service.redeem(redeemRequest, "lab.example");

        assertThat(redeemResponse.getClaims()).containsEntry("resourceType", "fmu");
        assertThat(redeemResponse.getClaims()).containsEntry("accessKey", "test.fmu");
        // Second redeem should also succeed — ticket is reusable within validity period
        var redeemResponse2 = service.redeem(redeemRequest, "lab.example");
        assertThat(redeemResponse2.getClaims()).containsEntry("resourceType", "fmu");
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
        ArgumentCaptor<String> ticketHash = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> encryptedClaims = ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(jdbcTemplate).update(
            org.mockito.ArgumentMatchers.contains("INSERT INTO fmu_session_tickets"),
            ticketHash.capture(),
            anyString(),
            anyString(),
            encryptedClaims.capture(),
            anyLong()
        );
        assertThat(ticketHash.getValue()).hasSize(64).doesNotContain(issueResponse.getSessionTicket());
        assertThat(encryptedClaims.getValue()).startsWith("v1.").doesNotContain("user-1");
    }

    @SuppressWarnings("unchecked")
    @Test
    void shouldRedeemPersistedTicketMultipleTimes() throws Exception {
        service = buildService(jdbcTemplate);

        long now = System.currentTimeMillis() / 1000;
        when(jdbcTemplate.update(org.mockito.ArgumentMatchers.contains("DELETE FROM fmu_session_tickets WHERE expires_at"), anyLong())).thenReturn(0);
        when(jdbcTemplate.query(anyString(), any(PreparedStatementSetter.class), any(ResultSetExtractor.class)))
            .thenAnswer(invocation -> {
                ResultSetExtractor<Object> extractor = invocation.getArgument(2, ResultSetExtractor.class);
                ResultSet resultSet = org.mockito.Mockito.mock(ResultSet.class);
                when(resultSet.next()).thenReturn(true);
                when(resultSet.getString(1)).thenReturn(ticketCipher.encrypt("""
                    {"sub":"user-1","labId":42,"accessKey":"test.fmu","resourceType":"fmu","reservationKey":"0xabc","targetGatewayId":"lab.example","nbf":%d,"exp":%d}
                    """.formatted(now - 30, now + 300).trim()));
                when(resultSet.getLong(2)).thenReturn(now + 120);
                return extractor.extractData(resultSet);
            });

        FmuSessionTicketRedeemRequest redeemRequest = new FmuSessionTicketRedeemRequest();
        redeemRequest.setSessionTicket("st_test");
        redeemRequest.setLabId("42");
        redeemRequest.setReservationKey("0xabc");

        var redeemResponse = service.redeem(redeemRequest, "lab.example");
        assertThat(redeemResponse.getClaims()).containsEntry("resourceType", "fmu");

        // Second redeem should also succeed — ticket is reusable within validity period
        var redeemResponse2 = service.redeem(redeemRequest, "lab.example");
        assertThat(redeemResponse2.getClaims()).containsEntry("resourceType", "fmu");
    }

    @Test
    void shouldRejectRedeemFromDifferentGateway() {
        long now = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = validClaims(now);
        when(jwtService.validateToken("booking-token")).thenReturn(true);
        when(jwtService.extractAllClaims("booking-token")).thenReturn(claims);

        var issueResponse = service.issue("Bearer booking-token", new FmuSessionTicketIssueRequest());
        FmuSessionTicketRedeemRequest redeemRequest = new FmuSessionTicketRedeemRequest();
        redeemRequest.setSessionTicket(issueResponse.getSessionTicket());

        assertThatThrownBy(() -> service.redeem(redeemRequest, "other.example"))
            .isInstanceOf(SessionTicketException.class)
            .extracting("code")
            .isEqualTo("GATEWAY_ID_MISMATCH");
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

    @Test
    void shouldFailClosedWhenPersistenceIsRequiredButUnavailable() {
        long now = System.currentTimeMillis() / 1000;
        when(jwtService.validateToken("booking-token")).thenReturn(true);
        when(jwtService.extractAllClaims("booking-token")).thenReturn(validClaims(now));
        ReflectionTestUtils.setField(service, "requirePersistence", true);

        assertThatThrownBy(() -> service.issue("Bearer booking-token", new FmuSessionTicketIssueRequest()))
            .isInstanceOf(SessionTicketException.class)
            .extracting("code")
            .isEqualTo("SESSION_TICKET_PERSISTENCE_UNAVAILABLE");
    }

    private FmuSessionTicketService buildService(JdbcTemplate template) {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(template);
        FmuSessionTicketService candidate = new FmuSessionTicketService(
            jwtService,
            jdbcTemplateProvider,
            accessCredentialAuditService,
            ticketCipher
        );
        ReflectionTestUtils.setField(candidate, "maxTtlSeconds", 300L);
        ReflectionTestUtils.setField(candidate, "requirePersistence", false);
        return candidate;
    }

    private Map<String, Object> validClaims(long now) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user-1");
        claims.put("labId", 42);
        claims.put("accessKey", "test.fmu");
        claims.put("resourceType", "fmu");
        claims.put("reservationKey", "0xabc");
        claims.put("targetGatewayId", "lab.example");
        claims.put("nbf", now - 30);
        claims.put("exp", now + 300);
        return claims;
    }
}
