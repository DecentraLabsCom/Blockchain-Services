package decentralabs.blockchain.config;

import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import io.reactivex.Flowable;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterNumber;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.Log;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ContractEventListenerConfigTest {

    @Mock
    private WalletService walletService;

    @Mock
    private LabMetadataService labMetadataService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private Web3j web3j;

    private ContractEventListenerConfig config;

    @BeforeEach
    void setUp() {
        config = new ContractEventListenerConfig(walletService, labMetadataService, institutionalWalletService);
        ReflectionTestUtils.setField(config, "diamondContractAddress", "0x1234567890abcdef");
        ReflectionTestUtils.setField(config, "startBlock", "latest");
    }

    @Test
    void shouldConfigureEventListenersForSupportedEvents() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested,ReservationConfirmed");
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        when(walletService.getWeb3jInstance()).thenReturn(web3j);
        when(web3j.ethLogFlowable(any(EthFilter.class))).thenReturn(Flowable.<Log>empty());

        config.configureContractEventListeners();

        verify(walletService).getWeb3jInstance();
        verify(web3j, times(2)).ethLogFlowable(any(EthFilter.class));
    }

    @Test
    void shouldSkipConfigurationWhenDisabled() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested");
        ReflectionTestUtils.setField(config, "eventListeningEnabled", false);

        config.configureContractEventListeners();

        verifyNoInteractions(walletService, labMetadataService);
        verify(web3j, never()).ethLogFlowable(any(EthFilter.class));
    }

    @Test
    void shouldFilterUnsupportedEventsDuringParsing() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested, UnknownEvent ,ReservationConfirmed");

        List<String> events = ReflectionTestUtils.invokeMethod(config, "parseConfiguredEvents");

        assertThat(events).containsExactly("ReservationRequested", "ReservationConfirmed");
    }

    @Test
    void shouldResolveHexadecimalStartBlock() {
        ReflectionTestUtils.setField(config, "startBlock", "0x10");

        DefaultBlockParameter result = ReflectionTestUtils.invokeMethod(config, "resolveStartBlockParameter");

        assertThat(result).isNotNull().isInstanceOf(DefaultBlockParameterNumber.class);
        if (result != null) {
            String value = ((DefaultBlockParameterNumber) result).getValue();
            BigInteger block = value.startsWith("0x")
                ? new BigInteger(value.substring(2), 16)
                : new BigInteger(value);
            assertThat(block).isEqualTo(BigInteger.valueOf(16));
        }
    }

    @Test
    void shouldRejectReservationKeysWithWrongLength() {
        assertThatThrownBy(() ->
            ReflectionTestUtils.invokeMethod(config, "reservationKeyToBytes", "0x1234")
        ).isInstanceOf(IllegalArgumentException.class);
    }
}
