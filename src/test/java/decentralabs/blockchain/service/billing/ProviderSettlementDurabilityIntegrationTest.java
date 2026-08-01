package decentralabs.blockchain.service.billing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = ProviderSettlementDurabilityIntegrationTest.TestConfig.class)
@Sql("/integration/billing-schema.sql")
class ProviderSettlementDurabilityIntegrationTest {

    @Configuration
    @EnableTransactionManagement
    static class TestConfig {

        @Bean
        DataSource dataSource() {
            SimpleDriverDataSource dataSource = new SimpleDriverDataSource();
            dataSource.setDriverClass(org.h2.Driver.class);
            dataSource.setUrl("jdbc:h2:mem:provider-settlement-durability;DB_CLOSE_DELAY=-1;MODE=MySQL");
            return dataSource;
        }

        @Bean
        JdbcTemplate jdbcTemplate(DataSource dataSource) {
            return new JdbcTemplate(dataSource);
        }

        @Bean
        PlatformTransactionManager transactionManager(DataSource dataSource) {
            return new DataSourceTransactionManager(dataSource);
        }

        @Bean
        ProviderSettlementPersistenceService providerSettlementPersistenceService(JdbcTemplate jdbcTemplate) {
            return new ProviderSettlementPersistenceService(objectProviderOf(jdbcTemplate));
        }

        @Bean
        ProviderSettlementChainClient providerSettlementChainClient() throws Exception {
            ProviderSettlementChainClient chainClient = mock(ProviderSettlementChainClient.class);
            doThrow(new IOException("RPC read unavailable")).when(chainClient).readClaim(any(byte[].class));
            when(chainClient.submit(
                any(byte[].class),
                any(BigInteger.class),
                any(BigInteger.class),
                any(byte[].class),
                any(byte[].class),
                anyString()
            )).thenAnswer(invocation -> {
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
                throw new IllegalStateException("simulated failure after broadcast acceptance");
            });
            return chainClient;
        }

        @Bean
        ProviderSettlementService providerSettlementService(
            ProviderSettlementPersistenceService persistence,
            ProviderSettlementChainClient chainClient,
            PlatformTransactionManager transactionManager
        ) {
            return new ProviderSettlementService(persistence, chainClient, transactionManager);
        }

        private static <T> org.springframework.beans.factory.ObjectProvider<T> objectProviderOf(T instance) {
            return new org.springframework.beans.factory.ObjectProvider<>() {
                @Override public T getObject() { return instance; }
                @Override public T getObject(Object... args) { return instance; }
                @Override public T getIfAvailable() { return instance; }
                @Override public T getIfUnique() { return instance; }
            };
        }
    }

    @Autowired
    private ProviderSettlementService providerSettlementService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanSettlementTables() {
        jdbcTemplate.execute("DELETE FROM provider_settlement_operations");
        jdbcTemplate.execute("DELETE FROM provider_approvals");
        jdbcTemplate.execute("DELETE FROM provider_payouts");
        jdbcTemplate.execute("DELETE FROM provider_invoice_records");
    }

    @Test
    void keepsSettlementOperationDurableWhenBroadcastPhaseFails() {
        assertThatThrownBy(() -> providerSettlementService.submitInvoice(
            "1",
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0001",
            "CLAIM-DURABILITY-1",
            "0x" + "11".repeat(32),
            "INV-DURABILITY-1",
            new BigDecimal("25.00"),
            new BigDecimal("250.00")
        )).isInstanceOf(IllegalStateException.class);

        assertThat(jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM provider_settlement_operations",
            Integer.class
        )).isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject(
            "SELECT status FROM provider_settlement_operations WHERE claim_id = ?",
            String.class,
            "CLAIM-DURABILITY-1"
        )).isEqualTo("PREPARED");
    }
}
