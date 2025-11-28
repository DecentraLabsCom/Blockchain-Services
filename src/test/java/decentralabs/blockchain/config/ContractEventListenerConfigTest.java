package decentralabs.blockchain.config;

import decentralabs.blockchain.notification.ReservationNotificationService;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.persistence.ReservationPersistenceService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.protocol.Web3j;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ContractEventListenerConfigTest {

    @Mock
    private EventPollingFallbackService eventPollingFallbackService;

    @Mock
    private WalletService walletService;

    @Mock
    private LabMetadataService labMetadataService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private ReservationNotificationService reservationNotificationService;

    @Mock
    private ReservationPersistenceService reservationPersistenceService;

    @Mock
    private Web3j web3j;

    private ContractEventListenerConfig config;

    @BeforeEach
    void setUp() {
        config = new ContractEventListenerConfig(
            eventPollingFallbackService,
            walletService,
            labMetadataService,
            institutionalWalletService,
            reservationNotificationService,
            reservationPersistenceService
        );
        ReflectionTestUtils.setField(config, "diamondContractAddress", "0x1234567890abcdef");
        ReflectionTestUtils.setField(config, "startBlock", "latest");
    }

    @Test
    void shouldConfigureEventListenersForSupportedEvents() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested,ReservationConfirmed");
        ReflectionTestUtils.setField(config, "eventListeningEnabled", true);

        when(walletService.getWeb3jInstance()).thenReturn(web3j);

        config.configureContractEventListeners();

        verify(walletService).getWeb3jInstance();
        verify(eventPollingFallbackService).initialize(web3j, "0x1234567890abcdef");
        verify(eventPollingFallbackService).start();
    }

    @Test
    void shouldSkipConfigurationWhenDisabled() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested");
        ReflectionTestUtils.setField(config, "eventListeningEnabled", false);

        config.configureContractEventListeners();

        verifyNoInteractions(walletService, labMetadataService, eventPollingFallbackService);
    }

    @Test
    void shouldFilterUnsupportedEventsDuringParsing() {
        ReflectionTestUtils.setField(config, "eventsToListen", "ReservationRequested, UnknownEvent ,ReservationConfirmed");

        List<String> events = ReflectionTestUtils.invokeMethod(config, "parseConfiguredEvents");

        assertThat(events).containsExactly("ReservationRequested", "ReservationConfirmed");
    }

    @Test
    void shouldRejectReservationKeysWithWrongLength() {
        assertThatThrownBy(() ->
            ReflectionTestUtils.invokeMethod(config, "reservationKeyToBytes", "0x1234")
        ).isInstanceOf(IllegalArgumentException.class);
    }
}
