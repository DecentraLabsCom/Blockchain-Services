package decentralabs.blockchain.service.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.AccessCredentialSessionObservedRequest;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.web3j.crypto.Credentials;

@ExtendWith(MockitoExtension.class)
class SessionStartedAttestationServiceTest {

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private WalletService walletService;

    @Test
    void shouldSignAndPersistSessionStartedAttestation() throws Exception {
        Credentials credentials = Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");
        SessionStartedAttestationService service = buildService(jdbcTemplate);
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(walletService.isLabOwnedByProvider(credentials.getAddress(), BigInteger.valueOf(42))).thenReturn(true);
        when(jdbcTemplate.query(anyString(), anyAuditCredentialRowMapper(), any(Object[].class)))
            .thenAnswer(invocation -> {
                RowMapper<?> mapper = invocation.getArgument(1);
                ResultSet rs = org.mockito.Mockito.mock(ResultSet.class);
                when(rs.getString("reservation_key")).thenReturn("0xabc");
                when(rs.getString("lab_id")).thenReturn("42");
                when(rs.getString("puc_hash")).thenReturn("0x" + "1".repeat(64));
                when(rs.getString("access_type")).thenReturn("guacamole");
                when(rs.getString("jwt_jti")).thenReturn("jwt-jti");
                when(rs.getString("fmu_ticket_id")).thenReturn(null);
                when(rs.getString("credential_hash")).thenReturn("a".repeat(64));
                return List.of(mapper.mapRow(rs, 0));
            });
        when(jdbcTemplate.update(anyString(), any(Object[].class))).thenReturn(1);

        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setJwtJti("jwt-jti");
        request.setSessionId("guac-session-1");
        request.setGatewayId("gateway-a");
        request.setAccessType("guacamole");

        boolean recorded = service.recordSessionStarted(request, 1_700_010_000L, "guacamole");

        org.assertj.core.api.Assertions.assertThat(recorded).isTrue();
        ArgumentCaptor<Object[]> args = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(ArgumentMatchers.contains("INSERT INTO session_started_attestations"), args.capture());
        org.assertj.core.api.Assertions.assertThat(args.getValue())
            .contains("0xabc", "42", "gateway-a", "guac-session-1", "guacamole", "jwt_jti", "jwt-jti")
            .doesNotContain("secret.jwt.value");
        org.assertj.core.api.Assertions.assertThat(args.getValue()[11].toString()).startsWith("0x").hasSize(66);
        org.assertj.core.api.Assertions.assertThat(args.getValue()[12].toString()).startsWith("0x").hasSize(132);
    }

    @Test
    void shouldSkipWhenLocalWalletDoesNotOwnLabOnChain() throws Exception {
        Credentials credentials = Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");
        SessionStartedAttestationService service = buildService(jdbcTemplate);
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(walletService.isLabOwnedByProvider(credentials.getAddress(), BigInteger.valueOf(42))).thenReturn(false);
        when(jdbcTemplate.query(anyString(), anyAuditCredentialRowMapper(), any(Object[].class)))
            .thenAnswer(invocation -> {
                RowMapper<?> mapper = invocation.getArgument(1);
                ResultSet rs = org.mockito.Mockito.mock(ResultSet.class);
                when(rs.getString("reservation_key")).thenReturn("0xabc");
                when(rs.getString("lab_id")).thenReturn("42");
                when(rs.getString("puc_hash")).thenReturn("0x" + "1".repeat(64));
                when(rs.getString("access_type")).thenReturn("guacamole");
                when(rs.getString("jwt_jti")).thenReturn("jwt-jti");
                when(rs.getString("fmu_ticket_id")).thenReturn(null);
                when(rs.getString("credential_hash")).thenReturn("a".repeat(64));
                return List.of(mapper.mapRow(rs, 0));
            });

        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setJwtJti("jwt-jti");
        request.setSessionId("guac-session-1");
        request.setGatewayId("gateway-a");
        request.setAccessType("guacamole");

        boolean recorded = service.recordSessionStarted(request, 1_700_010_000L, "guacamole");

        org.assertj.core.api.Assertions.assertThat(recorded).isFalse();
        verify(jdbcTemplate, never()).update(ArgumentMatchers.contains("INSERT INTO session_started_attestations"), any(Object[].class));
    }

    @Test
    void shouldSkipWhenDatasourceIsUnavailable() {
        SessionStartedAttestationService service = buildService(null);
        AccessCredentialSessionObservedRequest request = new AccessCredentialSessionObservedRequest();
        request.setReservationKey("0xabc");
        request.setJwtJti("jwt-jti");
        request.setSessionId("guac-session-1");

        boolean recorded = service.recordSessionStarted(request, 1_700_010_000L, "guacamole");

        org.assertj.core.api.Assertions.assertThat(recorded).isFalse();
        verify(institutionalWalletService, never()).getInstitutionalCredentials();
    }

    private SessionStartedAttestationService buildService(JdbcTemplate template) {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(template);
        return new SessionStartedAttestationService(
            jdbcTemplateProvider,
            institutionalWalletService,
            walletService,
            new SessionStartedAttestationSigner(
                "DecentraLabsSession",
                "1",
                11155111L,
                "0x2222222222222222222222222222222222222222"
            )
        );
    }

    private RowMapper<?> anyAuditCredentialRowMapper() {
        return ArgumentMatchers.<RowMapper<?>>any();
    }
}
