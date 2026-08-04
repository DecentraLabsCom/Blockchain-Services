package decentralabs.blockchain.config;

import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.intent.Eip712IntentVerifier;
import decentralabs.blockchain.service.intent.IntentPersistenceService;
import decentralabs.blockchain.service.intent.IntentRecord;
import decentralabs.blockchain.service.intent.IntentService;
import decentralabs.blockchain.service.intent.IntentWebhookService;
import decentralabs.blockchain.service.labadmin.LabContentRetentionService;
import decentralabs.blockchain.service.persistence.ProviderSettlementPersistenceService;
import decentralabs.blockchain.service.provider.DistributedReservationAvailabilityLockService;
import decentralabs.blockchain.service.provider.StationCapacityService;
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.utils.Numeric;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class ReservationIntentProcessedE2ETest {

    @Mock
    private EventPollingFallbackService eventPollingFallbackService;

    @Mock
    private InstitutionalTxManagerProvider txManagerProvider;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private DistributedReservationAvailabilityLockService reservationAvailabilityLockService;

    @Mock
    private StationCapacityService stationCapacityService;

    @Mock
    private WalletService walletService;

    @Mock
    private decentralabs.blockchain.service.health.LabMetadataService labMetadataService;

    @Mock
    private decentralabs.blockchain.notification.ReservationNotificationService reservationNotificationService;

    @Mock
    private decentralabs.blockchain.service.persistence.ReservationPersistenceService reservationPersistenceService;

    @Mock
    private ProviderSettlementPersistenceService providerSettlementPersistenceService;

    @Mock
    private LabContentRetentionService contentRetentionService;

    @Mock
    private IntentPersistenceService intentPersistenceService;

    @Mock
    private Eip712IntentVerifier verifier;

    @Mock
    private IntentWebhookService webhookService;

    @Mock
    private SamlValidationService samlValidationService;

    @Mock
    private WebauthnCredentialService webauthnCredentialService;

    @Mock
    private BackendUrlResolver backendUrlResolver;

    private IntentService intentService;
    private ContractEventListenerConfig listener;

    @BeforeEach
    void setUp() {
        intentService = new IntentService(
            "15s",
            60_000L,
            verifier,
            intentPersistenceService,
            webhookService,
            samlValidationService,
            webauthnCredentialService,
            walletService,
            "0x0000000000000000000000000000000000000001",
            new SimpleMeterRegistry(),
            backendUrlResolver
        );
        listener = new ContractEventListenerConfig(
            eventPollingFallbackService,
            txManagerProvider,
            institutionalWalletService,
            reservationAvailabilityLockService,
            stationCapacityService,
            walletService,
            labMetadataService,
            reservationNotificationService,
            reservationPersistenceService,
            intentPersistenceService,
            intentService,
            providerSettlementPersistenceService,
            contentRetentionService
        );
    }

    @Test
    void reconstructsIntentStateFromReservationIntentProcessedWhenLocalReceiptIsMissing() {
        String requestId = "0x" + "11".repeat(32);
        String reservationKey = "0x" + "22".repeat(32);
        String pucHash = "0x" + "33".repeat(32);
        String transactionHash = "0xevent-only-recovery";
        Event eventDefinition = supportedEvents().get("ReservationIntentProcessed");

        // This is the recovery path: there is no local transaction receipt to inspect.
        Log eventLog = new Log();
        eventLog.setTopics(List.of(
            EventEncoder.encode(eventDefinition),
            Numeric.toHexStringNoPrefixZeroPadded(Numeric.toBigInt(requestId), 64)
        ));
        eventLog.setData(encodeReservationIntentData(reservationKey, pucHash));
        eventLog.setTransactionHash(transactionHash);
        eventLog.setBlockNumber("0x2a");

        ReflectionTestUtils.invokeMethod(
            listener,
            "handleContractEvent",
            "ReservationIntentProcessed",
            eventDefinition,
            eventLog
        );

        IntentRecord recovered = intentService.findByRequestId(requestId).orElseThrow();
        assertThat(recovered.getStatus().getWireValue()).isEqualTo("executed");
        assertThat(recovered.getTxHash()).isEqualTo(transactionHash);
        assertThat(recovered.getBlockNumber()).isEqualTo(42L);
        assertThat(recovered.getReservationKey()).isEqualTo(reservationKey);
        assertThat(recovered.getPucHash()).isEqualTo(pucHash);
        verify(intentPersistenceService).upsert(any(IntentRecord.class));
        verify(webhookService).notify(recovered);
    }

    private Map<String, Event> supportedEvents() {
        @SuppressWarnings("unchecked")
        Map<String, Event> events = (Map<String, Event>) ReflectionTestUtils.getField(
            ContractEventListenerConfig.class,
            "SUPPORTED_EVENTS"
        );
        return events;
    }

    private String encodeReservationIntentData(String reservationKey, String pucHash) {
        String encoded = FunctionEncoder.encode(new Function(
            "ReservationIntentProcessedPayload",
            List.of(
                new Bytes32(Numeric.hexStringToByteArray(reservationKey)),
                new Utf8String("DIRECT_BOOKING"),
                new Bytes32(Numeric.hexStringToByteArray(pucHash)),
                new Address("0x00000000000000000000000000000000000000aa"),
                new Bool(true),
                new Utf8String("")
            ),
            List.of()
        ));
        return "0x" + encoded.substring(10);
    }
}
