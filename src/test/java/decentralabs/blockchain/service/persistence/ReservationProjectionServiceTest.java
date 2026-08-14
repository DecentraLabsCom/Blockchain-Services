package decentralabs.blockchain.service.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.service.wallet.WalletService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

class ReservationProjectionServiceTest {

    private ReservationProjectionService service;

    @BeforeEach
    void setUp() {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(mock(JdbcTemplate.class));
        service = new ReservationProjectionService(provider, new ObjectMapper(), mock(WalletService.class));
        ReflectionTestUtils.setField(
            service,
            "credentialsJson",
            "{\"lite.example\":{\"token\":\"rpr-secret\",\"accessUri\":\"https://LITE.example/\"}}"
        );
    }

    @Test
    void authenticatesOnlyTheConfiguredGatewayAndToken() {
        var credential = service.authenticate("LITE.EXAMPLE", "rpr-secret");

        assertThat(credential).isNotNull();
        assertThat(credential.gatewayId()).isEqualTo("lite.example");
        assertThat(credential.accessUri()).isEqualTo("https://lite.example");
        assertThat(service.authenticate("other.example", "rpr-secret")).isNull();
        assertThat(service.authenticate("lite.example", "wrong")).isNull();
    }

    @Test
    void rejectsCredentialWithoutAnHttpsOriginScope() {
        ReflectionTestUtils.setField(
            service,
            "credentialsJson",
            "{\"lite.example\":{\"token\":\"rpr-secret\",\"accessUri\":\"not-an-origin\"}}"
        );

        assertThat(service.authenticate("lite.example", "rpr-secret")).isNull();
    }
}
