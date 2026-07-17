package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.AccessCredentialSessionObservedRequest;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class AccessCredentialAuditServiceTest {

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private ObjectProvider<SessionStartedAttestationService> sessionStartedAttestationServiceProvider;

    @Mock
    private SessionStartedAttestationService sessionStartedAttestationService;

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Test
    void shouldPersistJwtCredentialWithoutRawToken() {
        AccessCredentialAuditService service = buildService(jdbcTemplate);
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);

        Map<String, Object> bookingInfo = Map.of(
            "reservationKey", "0xabc",
            "lab", BigInteger.valueOf(42),
            "resourceType", "lab",
            "sub", "dlabs-res-abc",
            "accessKey", "guac:id:7",
            "guacSessionId", "session-abc",
            "exp", BigInteger.valueOf(1_700_003_600L)
        );
        Map<String, Object> marketplaceClaims = Map.of(
            "puc", "User@University.EDU",
            "payerInstitutionWallet", "0xwallet"
        );
        JwtService.IssuedToken issuedToken =
            new JwtService.IssuedToken("secret.jwt.value", "session-abc", 1_700_000_000L, 1_700_003_600L);

        service.recordJwtIssued(marketplaceClaims, bookingInfo, issuedToken);

        ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(contains("INSERT INTO access_credential_audit"), args.capture());
        Object[] values = args.getValue();
        assertThatCode(() -> {
            org.assertj.core.api.Assertions.assertThat(values).contains("0xabc", "42", "guacamole", "session-abc");
            org.assertj.core.api.Assertions.assertThat(values).doesNotContain("secret.jwt.value");
        }).doesNotThrowAnyException();
    }

    @Test
    void shouldPersistFmuTicketCredentialWithoutRawTicket() {
        AccessCredentialAuditService service = buildService(jdbcTemplate);
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);

        Map<String, Object> claims = Map.of(
            "reservationKey", "0xabc",
            "labId", 42,
            "pucHash", "0x" + "ab".repeat(32),
            "jti", "jwt-jti",
            "exp", 1_700_003_600L
        );

        service.recordFmuTicketIssued("st_secret_ticket", claims, 1_700_003_600L);

        ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(contains("INSERT INTO access_credential_audit"), args.capture());
        Object[] values = args.getValue();
        assertThatCode(() -> {
            org.assertj.core.api.Assertions.assertThat(values).contains("0xabc", "42", "fmu", "jwt-jti");
            org.assertj.core.api.Assertions.assertThat(values).doesNotContain("st_secret_ticket");
        }).doesNotThrowAnyException();
    }

    @Test
    void shouldFailClosedForRequiredFmuTicketAuditWithoutDatasource() {
        AccessCredentialAuditService service = buildService(null);

        assertThatThrownBy(() -> service.recordFmuTicketIssuedRequired(
            "st_secret_ticket",
            Map.of("reservationKey", "0xabc"),
            1_700_003_600L
        ))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("requires a datasource");
    }

    @Test
    void shouldSkipWhenDatasourceIsUnavailable() {
        AccessCredentialAuditService service = buildService(null);

        service.recordJwtIssued(
            Map.of("puc", "user"),
            Map.of("reservationKey", "0xabc"),
            new JwtService.IssuedToken("token", "jti", 1L, 2L)
        );

        verify(jdbcTemplate, never()).update(anyString(), any(Object[].class));
    }

    @Test
    void shouldMarkSessionObservedByJwtJti() {
        AccessCredentialAuditService service = buildService(jdbcTemplate);
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(sessionStartedAttestationServiceProvider.getIfAvailable()).thenReturn(sessionStartedAttestationService);

        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setJwtJti("jwt-jti");
        request.setAccessType("guacamole");
        request.setSessionId("guac-session-1");
        request.setGatewayId("gateway-a");
        long observedAt = Instant.now().getEpochSecond();
        request.setObservedAt(observedAt);

        when(sessionStartedAttestationService.recordSessionStarted(request, observedAt, "guacamole"))
            .thenReturn(true);

        AccessCredentialAuditService.SessionObservationResult result = service.recordSessionObserved(request);

        org.assertj.core.api.Assertions.assertThat(result.auditRecorded()).isTrue();
        org.assertj.core.api.Assertions.assertThat(result.attestationRecorded()).isTrue();
        ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(contains("session_observed_at"), args.capture());
        org.assertj.core.api.Assertions.assertThat(args.getValue())
            .contains("guac-session-1", "gateway-a", "guacamole", "0xabc", "jwt-jti")
            .doesNotContain("secret.jwt.value");
        verify(sessionStartedAttestationService).recordSessionStarted(request, observedAt, "guacamole");
    }

    @Test
    void acceptsHistoricalObservedAtWhenReportedAtIsInsideObserverTokenWindow() {
        AccessCredentialAuditService service = buildService(jdbcTemplate);
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setJwtJti("jwt-jti");
        request.setGatewayId("gateway-a");
        request.setObservedAt(Instant.now().minusSeconds(600).getEpochSecond());
        long reportedAt = Instant.now().getEpochSecond();
        request.setReportedAt(reportedAt);

        AccessCredentialAuditService.SessionObservationResult result = service.recordSessionObserved(
            request,
            new AccessCredentialAuditService.ObserverTokenWindow(reportedAt - 1, reportedAt + 60)
        );

        org.assertj.core.api.Assertions.assertThat(result.auditRecorded()).isTrue();
        verify(jdbcTemplate).update(anyString(), any(Object[].class));
    }

    @Test
    void rejectsReportedAtOutsideTheShortLivedObserverTokenWindow() {
        AccessCredentialAuditService service = buildService(jdbcTemplate);
        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setJwtJti("jwt-jti");
        request.setGatewayId("gateway-a");
        request.setObservedAt(Instant.now().minusSeconds(600).getEpochSecond());
        long now = Instant.now().getEpochSecond();
        request.setReportedAt(now - 120);

        AccessCredentialAuditService.SessionObservationResult result = service.recordSessionObserved(
            request,
            new AccessCredentialAuditService.ObserverTokenWindow(now - 60, now + 60)
        );

        org.assertj.core.api.Assertions.assertThat(result.recorded()).isFalse();
        verify(jdbcTemplate, never()).update(anyString(), any(Object[].class));
    }

    @Test
    void shouldRequireAttestationBeforeConfirmingSessionObservationDelivery() {
        AccessCredentialAuditService service = buildService(jdbcTemplate);
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(sessionStartedAttestationServiceProvider.getIfAvailable()).thenReturn(sessionStartedAttestationService);
        when(sessionStartedAttestationService.recordSessionStarted(any(), org.mockito.ArgumentMatchers.anyLong(), anyString()))
            .thenReturn(false);

        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setJwtJti("jwt-jti");
        request.setSessionId("guac-session-1");
        request.setGatewayId("gateway-a");

        AccessCredentialAuditService.SessionObservationResult result = service.recordSessionObserved(request);

        org.assertj.core.api.Assertions.assertThat(result.auditRecorded()).isTrue();
        org.assertj.core.api.Assertions.assertThat(result.attestationRecorded()).isFalse();
        org.assertj.core.api.Assertions.assertThat(result.recorded()).isFalse();
    }

    @Test
    void shouldMarkFmuSessionObservedOnlyByTheRuntimeSuppliedTicketHash() {
        AccessCredentialAuditService service = buildService(jdbcTemplate);
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);
        when(sessionStartedAttestationServiceProvider.getIfAvailable()).thenReturn(sessionStartedAttestationService);
        when(sessionStartedAttestationService.recordSessionStarted(any(), org.mockito.ArgumentMatchers.anyLong(), anyString()))
            .thenReturn(true);

        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setFmuTicketId("a".repeat(64));
        request.setSessionId("sess-fmu-1");
        request.setGatewayId("gateway-a");
        request.setAccessType("fmu");
        request.setObservedAt(Instant.now().getEpochSecond());

        AccessCredentialAuditService.SessionObservationResult result = service.recordSessionObserved(request);

        org.assertj.core.api.Assertions.assertThat(result.recorded()).isTrue();
        ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(contains("session_observed_at"), args.capture());
        org.assertj.core.api.Assertions.assertThat(args.getValue())
            .contains("sess-fmu-1", "gateway-a", "fmu", "0xabc", "a".repeat(64))
            .doesNotContain("st_secret_ticket");
    }

    @Test
    void shouldReturnAuditEntriesForReservation() {
        AccessCredentialAuditService service = buildService(jdbcTemplate);
        when(jdbcTemplate.query(anyString(), anyAuditEntryRowMapper(), any(Object[].class)))
            .thenAnswer(invocation -> {
                RowMapper<AccessCredentialAuditService.AuditEntry> mapper = invocation.getArgument(1);
                java.sql.ResultSet rs = org.mockito.Mockito.mock(java.sql.ResultSet.class);
                when(rs.getString("reservation_key")).thenReturn("0xabc");
                when(rs.getString("lab_id")).thenReturn("42");
                when(rs.getString("puc_hash")).thenReturn("0xpuc");
                when(rs.getString("access_type")).thenReturn("guacamole");
                when(rs.getString("jwt_jti")).thenReturn("jwt-jti");
                when(rs.getString("guac_username")).thenReturn("user");
                when(rs.getString("fmu_ticket_id")).thenReturn(null);
                when(rs.getString("session_id")).thenReturn("guac-session-1");
                when(rs.getString("gateway_id")).thenReturn("gateway-a");
                when(rs.getString("target_gateway_id")).thenReturn("gateway-a");
                when(rs.getTimestamp("issued_at")).thenReturn(Timestamp.from(java.time.Instant.ofEpochSecond(1_700_000_000L)));
                when(rs.getTimestamp("expires_at")).thenReturn(Timestamp.from(java.time.Instant.ofEpochSecond(1_700_003_600L)));
                when(rs.getTimestamp("session_observed_at")).thenReturn(Timestamp.from(java.time.Instant.ofEpochSecond(1_700_010_000L)));
                when(rs.getString("session_observation_type")).thenReturn("guacamole");
                when(rs.getString("issuer_backend_id")).thenReturn("test-backend");
                when(rs.getString("credential_hash")).thenReturn("a".repeat(64));
                return List.of(mapper.mapRow(rs, 0));
            });

        List<AccessCredentialAuditService.AuditEntry> entries = service.findByReservationKey("0xabc");

        org.assertj.core.api.Assertions.assertThat(entries).hasSize(1);
        org.assertj.core.api.Assertions.assertThat(entries.getFirst().sessionObserved()).isTrue();
        org.assertj.core.api.Assertions.assertThat(entries.getFirst().credentialHash()).isEqualTo("a".repeat(64));
    }

    private AccessCredentialAuditService buildService(JdbcTemplate template) {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(template);
        AccessCredentialAuditService service = new AccessCredentialAuditService(
            jdbcTemplateProvider,
            sessionStartedAttestationServiceProvider
        );
        ReflectionTestUtils.setField(service, "issuerBackendId", "test-backend");
        ReflectionTestUtils.setField(service, "observationWindowToleranceSeconds", 30L);
        return service;
    }

    private RowMapper<AccessCredentialAuditService.AuditEntry> anyAuditEntryRowMapper() {
        return ArgumentMatchers.<RowMapper<AccessCredentialAuditService.AuditEntry>>any();
    }
}
