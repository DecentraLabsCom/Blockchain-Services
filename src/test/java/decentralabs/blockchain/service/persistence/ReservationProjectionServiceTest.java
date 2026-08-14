package decentralabs.blockchain.service.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.ContractGasProvider;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class ReservationProjectionServiceTest {

    private ReservationProjectionService service;
    private JdbcTemplate jdbcTemplate;
    private WalletService walletService;
    private Web3j web3j;
    private Diamond diamond;

    @BeforeEach
    void setUp() {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        jdbcTemplate = mock(JdbcTemplate.class);
        walletService = mock(WalletService.class);
        web3j = mock(Web3j.class);
        diamond = mock(Diamond.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        service = new ReservationProjectionService(provider, new ObjectMapper(), walletService);
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

    @Test
    void projectionReadDoesNotPersistLegacyAccessUri() throws Exception {
        var credential = service.authenticate("lite.example", "rpr-secret");
        ResultSet row = mock(ResultSet.class);
        when(row.getString("transaction_hash")).thenReturn("0xlegacy");
        when(row.getString("lab_id")).thenReturn("42");
        when(row.getTimestamp("start_time"))
            .thenReturn(Timestamp.from(Instant.parse("2026-08-14T10:30:00Z")));
        when(row.getTimestamp("end_time"))
            .thenReturn(Timestamp.from(Instant.parse("2026-08-14T11:30:00Z")));
        when(row.getString("status")).thenReturn("CONFIRMED");
        when(row.getString("access_uri")).thenReturn(null);
        doAnswer(invocation -> {
            RowMapper<Object> mapper = invocation.getArgument(2);
            return List.of(mapper.mapRow(row, 0));
        }).when(jdbcTemplate).query(
            anyString(),
            any(PreparedStatementSetter.class),
            ArgumentMatchers.<RowMapper<Object>>any()
        );

        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        Diamond.Lab lab = new Diamond.Lab(
            BigInteger.valueOf(42),
            new Diamond.LabBase(
                "https://metadata.example/lab.json",
                BigInteger.ZERO,
                "https://lite.example",
                "guac:id:42",
                BigInteger.ZERO,
                BigInteger.ZERO
            )
        );
        @SuppressWarnings("unchecked")
        RemoteFunctionCall<Diamond.Lab> getLab = mock(RemoteFunctionCall.class);
        when(getLab.send()).thenReturn(lab);
        when(diamond.getLab(BigInteger.valueOf(42))).thenReturn(getLab);
        ReflectionTestUtils.setField(service, "contractAddress", "0xcontract");

        try (MockedStatic<Diamond> diamondLoader = Mockito.mockStatic(Diamond.class)) {
            diamondLoader.when(() -> Diamond.load(
                anyString(),
                any(Web3j.class),
                any(ReadonlyTransactionManager.class),
                any(ContractGasProvider.class)
            )).thenReturn(diamond);

            List<ReservationProjectionService.ReservationProjection> projections =
                service.findReservations(
                    credential,
                    Instant.parse("2026-08-14T10:00:00Z"),
                    Instant.parse("2026-08-14T12:00:00Z"),
                    200
                );

            assertThat(projections).hasSize(1);
            assertThat(projections.getFirst().transactionHash()).isEqualTo("0xlegacy");
        }

        verify(jdbcTemplate, never()).update(anyString(), any(Object[].class));
    }
}
