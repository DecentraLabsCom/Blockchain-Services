package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;

class AccessAuthorizationProvisioningServiceTest {

    @Test
    @SuppressWarnings("unchecked")
    void acquiredLeaseCarriesAFencingToken() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.update(any(String.class), any(Object[].class))).thenReturn(0, 1);
        AccessAuthorizationProvisioningService service = new AccessAuthorizationProvisioningService(provider);

        AccessAuthorizationProvisioningService.ProvisioningLease lease = service.tryStart("0xreservation");

        assertThat(lease).isNotNull();
        assertThat(lease.fencingToken()).isNotBlank();
        verify(jdbcTemplate).update(
            contains("INSERT IGNORE INTO access_authorization_provisioning"),
            eq("0xreservation"),
            any(String.class),
            any(),
            any()
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void staleLeaseCannotFinalizeANewerProvisioningAttempt() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.update(contains("status = 'DELIVERED'"), any(), any())).thenReturn(0);
        AccessAuthorizationProvisioningService service = new AccessAuthorizationProvisioningService(provider);
        var staleLease = new AccessAuthorizationProvisioningService.ProvisioningLease("0xreservation", "stale-token", 1L);

        assertThat(service.markDelivered(staleLease)).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void rollbackMustAtomicallyClaimItsOwnLeaseBeforeDeletingProvisionedAccess() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.update(contains("ROLLING_BACK"), any(), any())).thenReturn(0);
        AccessAuthorizationProvisioningService service = new AccessAuthorizationProvisioningService(provider);
        var staleLease = new AccessAuthorizationProvisioningService.ProvisioningLease("0xreservation", "stale-token", 1L);

        assertThat(service.beginRollback(staleLease)).isFalse();
    }
}
