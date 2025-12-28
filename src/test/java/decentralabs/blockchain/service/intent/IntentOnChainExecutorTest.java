package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthChainId;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.intent.IntentOnChainExecutor.ExecutionResult;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;

@ExtendWith(MockitoExtension.class)
@DisplayName("IntentOnChainExecutor Tests")
class IntentOnChainExecutorTest {

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private Web3j web3j;

    @Mock
    private Request<?, EthChainId> chainIdRequest;

    private IntentOnChainExecutor executor;

    private static final String CONTRACT_ADDRESS = "0x1234567890123456789012345678901234567890";
    private static final BigInteger GAS_LIMIT = BigInteger.valueOf(300000);
    private static final BigInteger GAS_PRICE_GWEI = BigInteger.ONE;

    // Test credentials - generated from a known private key for testing
    private static final String TEST_PRIVATE_KEY = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    private Credentials testCredentials;

    @BeforeEach
    void setUp() {
        executor = new IntentOnChainExecutor(
            walletService,
            institutionalWalletService,
            CONTRACT_ADDRESS,
            GAS_LIMIT,
            GAS_PRICE_GWEI
        );

        // Create test credentials
        ECKeyPair keyPair = ECKeyPair.create(new BigInteger(TEST_PRIVATE_KEY.substring(2), 16));
        testCredentials = Credentials.create(keyPair);
    }

    @Nested
    @DisplayName("Action Routing Tests")
    class ActionRoutingTests {

        @Test
        @DisplayName("Should return unsupported_action for unknown action")
        void shouldReturnUnsupportedActionForUnknownAction() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "UNKNOWN_ACTION", "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("unsupported_action");
            assertThat(result.txHash()).isNull();
        }

        @Test
        @DisplayName("Should return unsupported_action for null action")
        void shouldReturnUnsupportedActionForNullAction() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", null, "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("unsupported_action");
        }

        @Test
        @DisplayName("Should handle action case insensitively")
        void shouldHandleActionCaseInsensitively() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            // Test with lowercase - should still match LAB_ADD
            IntentRecord record = new IntentRecord("req-123", "lab_add", "0xprovider");
            // No payload, so it should fail with missing_parameters, not unsupported_action

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("LAB_ADD Action Tests")
    class LabAddActionTests {

        @Test
        @DisplayName("Should return missing_parameters when payload is null")
        void shouldReturnMissingParametersWhenPayloadIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_ADD", "0xprovider");
            // No action payload set

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters when URI is null")
        void shouldReturnMissingParametersWhenUriIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_ADD", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setPrice(BigInteger.valueOf(100));
            // URI is null
            record.setActionPayload(payload);

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters when price is null")
        void shouldReturnMissingParametersWhenPriceIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_ADD", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setUri("ipfs://test");
            // Price is null
            record.setActionPayload(payload);

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("LAB_ADD_AND_LIST Action Tests")
    class LabAddAndListActionTests {

        @Test
        @DisplayName("Should return unsupported_action for LAB_ADD_AND_LIST")
        void shouldReturnUnsupportedActionWhenLabAddAndList() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_ADD_AND_LIST", "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("unsupported_action");
        }
    }

    @Nested
    @DisplayName("LAB_UPDATE Action Tests")
    class LabUpdateActionTests {

        @Test
        @DisplayName("Should return missing_parameters when payload is null for LAB_UPDATE")
        void shouldReturnMissingParametersWhenPayloadIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_UPDATE", "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters when labId is null for LAB_UPDATE")
        void shouldReturnMissingParametersWhenLabIdIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_UPDATE", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setUri("ipfs://updated");
            record.setActionPayload(payload);
            // labId is null

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("Simple Actions Tests (LIST, UNLIST, DELETE)")
    class SimpleActionsTests {

        @Test
        @DisplayName("Should return missing_parameters for LAB_LIST without labId")
        void shouldReturnMissingParametersForLabListWithoutLabId() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_LIST", "0xprovider");
            // No labId set

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters for LAB_UNLIST without labId")
        void shouldReturnMissingParametersForLabUnlistWithoutLabId() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_UNLIST", "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters for LAB_DELETE without labId")
        void shouldReturnMissingParametersForLabDeleteWithoutLabId() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_DELETE", "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("LAB_SET_URI Action Tests")
    class LabSetUriActionTests {

        @Test
        @DisplayName("Should return missing_parameters when payload is null for LAB_SET_URI")
        void shouldReturnMissingParametersWhenPayloadIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_SET_URI", "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("CANCEL_RESERVATION_REQUEST Action Tests")
    class CancelReservationRequestTests {

        @Test
        @DisplayName("Should return missing_parameters when reservationKey is null")
        void shouldReturnMissingParametersWhenReservationKeyIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "CANCEL_RESERVATION_REQUEST", "0xprovider");
            // No reservationKey set

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters when reservationKey is not 32 bytes")
        void shouldReturnMissingParametersWhenReservationKeyInvalidLength() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "CANCEL_RESERVATION_REQUEST", "0xprovider");
            record.setReservationKey("0x1234"); // Too short

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("RESERVATION_REQUEST Action Tests")
    class ReservationRequestTests {

        @Test
        @DisplayName("Should return missing_parameters when reservationPayload is null")
        void shouldReturnMissingParametersWhenReservationPayloadIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "RESERVATION_REQUEST", "0xprovider");
            // No reservation payload

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters when labId is null in reservation")
        void shouldReturnMissingParametersWhenLabIdIsNullInReservation() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "RESERVATION_REQUEST", "0xprovider");
            ReservationIntentPayload payload = new ReservationIntentPayload();
            payload.setStart(1000L);
            payload.setEnd(4600L);
            // labId is null
            record.setReservationPayload(payload);

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("CANCEL_BOOKING Action Tests")
    class CancelBookingTests {

        @Test
        @DisplayName("Should return missing_parameters when reservationKey is null for CANCEL_BOOKING")
        void shouldReturnMissingParametersWhenReservationKeyIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "CANCEL_BOOKING", "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters when reservationKey is invalid length")
        void shouldReturnMissingParametersWhenReservationKeyInvalidLength() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "CANCEL_BOOKING", "0xprovider");
            record.setReservationKey("0xabc"); // Invalid length

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("REQUEST_FUNDS Action Tests")
    class RequestFundsTests {

        @Test
        @DisplayName("Should return missing_parameters when actionPayload is null")
        void shouldReturnMissingParametersWhenPayloadIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "REQUEST_FUNDS", "0xprovider");

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }
    }

    @Nested
    @DisplayName("ExecutionResult Record Tests")
    class ExecutionResultTests {

        @Test
        @DisplayName("Should create ExecutionResult with all fields")
        void shouldCreateExecutionResultWithAllFields() {
            ExecutionResult result = new ExecutionResult(
                true,
                "0xtxhash",
                12345L,
                "lab-1",
                "0xreservationkey",
                null
            );

            assertThat(result.success()).isTrue();
            assertThat(result.txHash()).isEqualTo("0xtxhash");
            assertThat(result.blockNumber()).isEqualTo(12345L);
            assertThat(result.labId()).isEqualTo("lab-1");
            assertThat(result.reservationKey()).isEqualTo("0xreservationkey");
            assertThat(result.reason()).isNull();
        }

        @Test
        @DisplayName("Should create failed ExecutionResult with reason")
        void shouldCreateFailedExecutionResultWithReason() {
            ExecutionResult result = new ExecutionResult(
                false,
                null,
                null,
                null,
                null,
                "contract_reverted"
            );

            assertThat(result.success()).isFalse();
            assertThat(result.txHash()).isNull();
            assertThat(result.reason()).isEqualTo("contract_reverted");
        }
    }
}
