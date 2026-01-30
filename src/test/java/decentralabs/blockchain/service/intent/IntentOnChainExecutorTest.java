package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import java.math.BigDecimal;
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
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
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
    private InstitutionalTxManagerProvider txManagerProvider;

    @Mock
    private Web3j web3j;

    @Mock
    private Request<?, EthChainId> chainIdRequest;

    private IntentOnChainExecutor executor;

    private static final String CONTRACT_ADDRESS = "0x1234567890123456789012345678901234567890";
    private static final BigInteger GAS_LIMIT = BigInteger.valueOf(300000);
    private static final BigInteger GAS_PRICE_GWEI = BigInteger.ONE;
    private static final BigDecimal GAS_PRICE_MULTIPLIER = new BigDecimal("1.2");
    private static final BigDecimal GAS_PRICE_MIN_GWEI = BigDecimal.ONE;

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
            GAS_PRICE_GWEI,
            GAS_PRICE_MULTIPLIER,
            GAS_PRICE_MIN_GWEI,
            txManagerProvider
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
        @DisplayName("Should return missing_parameters when payload is null")
        void shouldReturnMissingParametersWhenPayloadIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_ADD_AND_LIST", "0xprovider");
            // No action payload set

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should return missing_parameters when URI is null")
        void shouldReturnMissingParametersWhenUriIsNull() throws Exception {
            when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(testCredentials);

            IntentRecord record = new IntentRecord("req-123", "LAB_ADD_AND_LIST", "0xprovider");
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

            IntentRecord record = new IntentRecord("req-123", "LAB_ADD_AND_LIST", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setUri("ipfs://test");
            // Price is null
            record.setActionPayload(payload);

            ExecutionResult result = executor.execute(record);

            assertThat(result.success()).isFalse();
            assertThat(result.reason()).isEqualTo("missing_parameters");
        }

        @Test
        @DisplayName("Should build addAndList Function with correct struct")
        void shouldBuildAddAndListFunction() throws Exception {
            IntentRecord record = new IntentRecord("req-abc", "LAB_ADD_AND_LIST", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x1111111111111111111111111111111111111111");
            payload.setSchacHomeOrganization("org-example");
            payload.setPuc("puc-value");
            payload.setAssertionHash("0x0000000000000000000000000000000000000000000000000000000000000000");
            payload.setLabId(BigInteger.ZERO);
            payload.setReservationKey("0x0000000000000000000000000000000000000000000000000000000000000000");
            payload.setUri("ipfs://test");
            payload.setPrice(BigInteger.valueOf(100));
            payload.setMaxBatch(BigInteger.ONE);
            payload.setAccessURI("access://");
            payload.setAccessKey("key");
            payload.setTokenURI("token://");
            record.setActionPayload(payload);

            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildAddAndList", IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("addAndListLabWithIntent");
            assertThat(f.getInputParameters()).hasSize(2);

            org.web3j.abi.datatypes.DynamicStruct ds = (org.web3j.abi.datatypes.DynamicStruct) f.getInputParameters().get(1);
            java.util.List<org.web3j.abi.datatypes.Type> values = ds.getValue();
            // executor
            org.web3j.abi.datatypes.Address addr = (org.web3j.abi.datatypes.Address) values.get(0);
            assertThat(addr.toString()).isEqualTo(payload.getExecutor());
            // uri
            org.web3j.abi.datatypes.Utf8String uri = (org.web3j.abi.datatypes.Utf8String) values.get(6);
            assertThat(uri.getValue()).isEqualTo(payload.getUri());
            // price
            org.web3j.abi.datatypes.generated.Uint96 price = (org.web3j.abi.datatypes.generated.Uint96) values.get(7);
            assertThat(price.getValue()).isEqualTo(payload.getPrice());
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
    @DisplayName("Builders Positive Tests")
    class BuildersPositiveTests {

        @Test
        @DisplayName("buildAdd builds addLabWithIntent function")
        void buildAddBuildsAddLab() throws Exception {
            IntentRecord record = new IntentRecord("req-add", "LAB_ADD", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x1111111111111111111111111111111111111111");
            payload.setUri("ipfs://add");
            payload.setPrice(BigInteger.valueOf(50));
            payload.setLabId(BigInteger.ZERO);
            record.setActionPayload(payload);

            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildAddLab", IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("addLabWithIntent");
            org.web3j.abi.datatypes.DynamicStruct ds = (org.web3j.abi.datatypes.DynamicStruct) f.getInputParameters().get(1);
            java.util.List<org.web3j.abi.datatypes.Type> values = ds.getValue();
            org.web3j.abi.datatypes.Utf8String uri = (org.web3j.abi.datatypes.Utf8String) values.get(6);
            org.web3j.abi.datatypes.generated.Uint96 price = (org.web3j.abi.datatypes.generated.Uint96) values.get(7);
            assertThat(uri.getValue()).isEqualTo(payload.getUri());
            assertThat(price.getValue()).isEqualTo(payload.getPrice());
        }

        @Test
        @DisplayName("buildUpdate builds updateLabWithIntent function")
        void buildUpdateBuildsUpdateLab() throws Exception {
            IntentRecord record = new IntentRecord("req-upd", "LAB_UPDATE", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x2222222222222222222222222222222222222222");
            payload.setLabId(BigInteger.valueOf(42));
            payload.setUri("ipfs://upd");
            payload.setPrice(BigInteger.valueOf(75));
            record.setActionPayload(payload);

            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildUpdateLab", IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("updateLabWithIntent");
            org.web3j.abi.datatypes.DynamicStruct ds = (org.web3j.abi.datatypes.DynamicStruct) f.getInputParameters().get(1);
            java.util.List<org.web3j.abi.datatypes.Type> values = ds.getValue();
            org.web3j.abi.datatypes.generated.Uint256 labId = (org.web3j.abi.datatypes.generated.Uint256) values.get(4);
            org.web3j.abi.datatypes.Utf8String uri = (org.web3j.abi.datatypes.Utf8String) values.get(6);
            assertThat(labId.getValue()).isEqualTo(payload.getLabId());
            assertThat(uri.getValue()).isEqualTo(payload.getUri());
        }

        @Test
        @DisplayName("buildSimple builds list/unlist/delete functions")
        void buildSimpleBuildsListUnlistDelete() throws Exception {
            IntentRecord record = new IntentRecord("req-simple", "LAB_LIST", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x3333333333333333333333333333333333333333");
            payload.setLabId(BigInteger.valueOf(7));
            record.setActionPayload(payload);

            Class<?> fnClass = Class.forName("decentralabs.blockchain.service.intent.IntentOnChainExecutor$FunctionName").asSubclass(Enum.class);
            Object listConst = java.lang.Enum.valueOf((Class) fnClass, "LIST_TOKEN");
            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildSimple", fnClass, IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, listConst, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("listLabWithIntent");

            Object unlistConst = java.lang.Enum.valueOf((Class) fnClass, "UNLIST_TOKEN");
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe2 = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, unlistConst, record);
            assertThat(maybe2).isPresent();
            assertThat(maybe2.get().getName()).isEqualTo("unlistLabWithIntent");

            Object deleteConst = java.lang.Enum.valueOf((Class) fnClass, "DELETE_LAB");
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe3 = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, deleteConst, record);
            assertThat(maybe3).isPresent();
            assertThat(maybe3.get().getName()).isEqualTo("deleteLabWithIntent");
        }

        @Test
        @DisplayName("buildSetTokenURI builds setTokenURIWithIntent")
        void buildSetTokenURI() throws Exception {
            IntentRecord record = new IntentRecord("req-token", "LAB_SET_URI", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x4444444444444444444444444444444444444444");
            payload.setLabId(BigInteger.valueOf(9));
            payload.setTokenURI("token://1");
            record.setActionPayload(payload);

            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildSetTokenURI", IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("setTokenURIWithIntent");
            org.web3j.abi.datatypes.DynamicStruct ds = (org.web3j.abi.datatypes.DynamicStruct) f.getInputParameters().get(1);
            java.util.List<org.web3j.abi.datatypes.Type> values = ds.getValue();
            org.web3j.abi.datatypes.Utf8String tokenUri = (org.web3j.abi.datatypes.Utf8String) values.get(11);
            assertThat(tokenUri.getValue()).isEqualTo(payload.getTokenURI());
        }

        @Test
        @DisplayName("buildRequestFunds builds requestFundsWithIntent with maxBatch")
        void buildRequestFunds() throws Exception {
            IntentRecord record = new IntentRecord("req-funds", "REQUEST_FUNDS", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x5555555555555555555555555555555555555555");
            payload.setLabId(BigInteger.valueOf(11));
            payload.setMaxBatch(BigInteger.valueOf(5));
            payload.setPrice(BigInteger.valueOf(0));
            record.setActionPayload(payload);

            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildRequestFunds", IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("requestFundsWithIntent");
            org.web3j.abi.datatypes.DynamicStruct ds = (org.web3j.abi.datatypes.DynamicStruct) f.getInputParameters().get(1);
            java.util.List<org.web3j.abi.datatypes.Type> values = ds.getValue();
            org.web3j.abi.datatypes.generated.Uint96 maxBatch = (org.web3j.abi.datatypes.generated.Uint96) values.get(8);
            assertThat(maxBatch.getValue()).isEqualTo(payload.getMaxBatch());
        }

        @Test
        @DisplayName("buildReservationRequest builds institutionalReservationRequestWithIntent")
        void buildReservationRequest() throws Exception {
            IntentRecord record = new IntentRecord("req-res", "RESERVATION_REQUEST", "0xprovider");
            ReservationIntentPayload payload = new ReservationIntentPayload();
            payload.setExecutor("0x6666666666666666666666666666666666666666");
            payload.setLabId(BigInteger.valueOf(13));
            payload.setStart(1000L);
            payload.setEnd(2000L);
            payload.setPrice(BigInteger.valueOf(10));
            payload.setReservationKey("0x0000000000000000000000000000000000000000000000000000000000000000");
            record.setReservationPayload(payload);

            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildReservationRequest", IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("institutionalReservationRequestWithIntent");
            org.web3j.abi.datatypes.DynamicStruct ds = (org.web3j.abi.datatypes.DynamicStruct) f.getInputParameters().get(1);
            java.util.List<org.web3j.abi.datatypes.Type> values = ds.getValue();
            org.web3j.abi.datatypes.generated.Uint32 start = (org.web3j.abi.datatypes.generated.Uint32) values.get(5);
            org.web3j.abi.datatypes.generated.Uint32 end = (org.web3j.abi.datatypes.generated.Uint32) values.get(6);
            assertThat(start.getValue().longValue()).isEqualTo(1000L);
            assertThat(end.getValue().longValue()).isEqualTo(2000L);
        }

        @Test
        @DisplayName("buildCancelReservation builds cancelInstitutionalReservationRequestWithIntent")
        void buildCancelReservation() throws Exception {
            IntentRecord record = new IntentRecord("req-cancel-res", "CANCEL_RESERVATION_REQUEST", "0xprovider");
            ReservationIntentPayload payload = new ReservationIntentPayload();
            payload.setExecutor("0x7777777777777777777777777777777777777777");
            payload.setLabId(BigInteger.valueOf(15));
            payload.setStart(3000L);
            payload.setEnd(4000L);
            payload.setPrice(BigInteger.valueOf(20));
            payload.setReservationKey("0x0000000000000000000000000000000000000000000000000000000000000000");
            record.setReservationPayload(payload);
            record.setReservationKey("0x0000000000000000000000000000000000000000000000000000000000000000");

            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildCancelReservation", IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("cancelInstitutionalReservationRequestWithIntent");
        }

        @Test
        @DisplayName("buildCancelBooking builds cancelInstitutionalBookingWithIntent")
        void buildCancelBooking() throws Exception {
            IntentRecord record = new IntentRecord("req-cancel-book", "CANCEL_BOOKING", "0xprovider");
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x8888888888888888888888888888888888888888");
            payload.setLabId(BigInteger.valueOf(17));
            payload.setReservationKey("0x0000000000000000000000000000000000000000000000000000000000000000");
            payload.setPrice(BigInteger.valueOf(5));
            record.setActionPayload(payload);
            record.setReservationKey("0x0000000000000000000000000000000000000000000000000000000000000000");

            java.lang.reflect.Method m = IntentOnChainExecutor.class.getDeclaredMethod("buildCancelBooking", IntentRecord.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Optional<org.web3j.abi.datatypes.Function> maybe = (java.util.Optional<org.web3j.abi.datatypes.Function>) m.invoke(executor, record);
            assertThat(maybe).isPresent();
            org.web3j.abi.datatypes.Function f = maybe.get();
            assertThat(f.getName()).isEqualTo("cancelInstitutionalBookingWithIntent");
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
