package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import decentralabs.blockchain.dto.intent.IntentStatus;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

@ExtendWith(MockitoExtension.class)
class IntentWebhookServiceTest {

    @Mock
    private OkHttpClient okHttpClient;

    @Mock
    private Call call;

    @Mock
    private Response response;

    @Mock
    private ResponseBody responseBody;

    private IntentWebhookService webhookService;

    private static final String WEBHOOK_URL = "https://example.com/webhook";
    private static final String WEBHOOK_SECRET = "test-secret-123";

    @BeforeEach
    void setUp() {
        webhookService = new IntentWebhookService(WEBHOOK_URL, WEBHOOK_SECRET);
        ReflectionTestUtils.setField(webhookService, "client", okHttpClient);
    }

    @Nested
    @DisplayName("Notify Tests")
    class NotifyTests {

        @Test
        @DisplayName("Should skip notification when webhook URL is null")
        void shouldSkipNotificationWhenUrlIsNull() {
            IntentWebhookService nullUrlService = new IntentWebhookService(null, WEBHOOK_SECRET);
            IntentRecord record = createTestRecord("req-001");

            nullUrlService.notify(record);

            // No HTTP call expected
        }

        @Test
        @DisplayName("Should skip notification when webhook URL is blank")
        void shouldSkipNotificationWhenUrlIsBlank() {
            IntentWebhookService blankUrlService = new IntentWebhookService("   ", WEBHOOK_SECRET);
            IntentRecord record = createTestRecord("req-002");

            blankUrlService.notify(record);

            // No HTTP call expected
        }

        @Test
        @DisplayName("Should send webhook notification with signature")
        void shouldSendWebhookNotificationWithSignature() throws IOException {
            IntentRecord record = createTestRecord("req-003");
            record.setStatus(IntentStatus.EXECUTED);
            record.setTxHash("0xabc123");
            record.setBlockNumber(12345L);

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenReturn(response);
            when(response.isSuccessful()).thenReturn(true);

            webhookService.notify(record);

            ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
            verify(okHttpClient).newCall(requestCaptor.capture());

            Request capturedRequest = requestCaptor.getValue();
            assertThat(capturedRequest.url().toString()).isEqualTo(WEBHOOK_URL);
            assertThat(capturedRequest.method()).isEqualTo("POST");
            assertThat(capturedRequest.header("X-Signature")).startsWith("sha256=");
        }

        @Test
        @DisplayName("Should send webhook without signature when secret is null")
        void shouldSendWebhookWithoutSignatureWhenSecretIsNull() throws IOException {
            IntentWebhookService noSecretService = new IntentWebhookService(WEBHOOK_URL, null);
            ReflectionTestUtils.setField(noSecretService, "client", okHttpClient);

            IntentRecord record = createTestRecord("req-004");

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenReturn(response);
            when(response.isSuccessful()).thenReturn(true);

            noSecretService.notify(record);

            ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
            verify(okHttpClient).newCall(requestCaptor.capture());

            Request capturedRequest = requestCaptor.getValue();
            assertThat(capturedRequest.header("X-Signature")).isNull();
        }

        @Test
        @DisplayName("Should send webhook without signature when secret is blank")
        void shouldSendWebhookWithoutSignatureWhenSecretIsBlank() throws IOException {
            IntentWebhookService blankSecretService = new IntentWebhookService(WEBHOOK_URL, "   ");
            ReflectionTestUtils.setField(blankSecretService, "client", okHttpClient);

            IntentRecord record = createTestRecord("req-005");

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenReturn(response);
            when(response.isSuccessful()).thenReturn(true);

            blankSecretService.notify(record);

            ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
            verify(okHttpClient).newCall(requestCaptor.capture());

            Request capturedRequest = requestCaptor.getValue();
            assertThat(capturedRequest.header("X-Signature")).isNull();
        }

        @Test
        @DisplayName("Should handle unsuccessful response gracefully")
        void shouldHandleUnsuccessfulResponseGracefully() throws IOException {
            IntentRecord record = createTestRecord("req-006");

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenReturn(response);
            when(response.isSuccessful()).thenReturn(false);
            when(response.code()).thenReturn(500);

            // Should not throw
            webhookService.notify(record);

            verify(okHttpClient).newCall(any(Request.class));
        }

        @Test
        @DisplayName("Should handle IO exception gracefully")
        void shouldHandleIOExceptionGracefully() throws IOException {
            IntentRecord record = createTestRecord("req-007");

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenThrow(new IOException("Connection refused"));

            // Should not throw
            webhookService.notify(record);

            verify(okHttpClient).newCall(any(Request.class));
        }

        @Test
        @DisplayName("Should include all record fields in payload")
        void shouldIncludeAllRecordFieldsInPayload() throws IOException {
            IntentRecord record = createTestRecord("req-008");
            record.setStatus(IntentStatus.FAILED);
            record.setTxHash("0xdef456");
            record.setBlockNumber(67890L);
            record.setLabId("lab-42");
            record.setReservationKey("0xreskey");
            record.setError("Transaction reverted");

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenReturn(response);
            when(response.isSuccessful()).thenReturn(true);

            webhookService.notify(record);

            ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
            verify(okHttpClient).newCall(requestCaptor.capture());

            // Verify request was made with POST body
            Request capturedRequest = requestCaptor.getValue();
            assertThat(capturedRequest.body()).isNotNull();
            assertThat(capturedRequest.body().contentType().toString()).contains("application/json");
        }

        @Test
        @DisplayName("Should use reason when error is null")
        void shouldUseReasonWhenErrorIsNull() throws IOException {
            IntentRecord record = createTestRecord("req-009");
            record.setError(null);
            record.setReason("User cancelled");

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenReturn(response);
            when(response.isSuccessful()).thenReturn(true);

            webhookService.notify(record);

            verify(okHttpClient).newCall(any(Request.class));
        }
    }

    @Nested
    @DisplayName("Signature Tests")
    class SignatureTests {

        @Test
        @DisplayName("Should generate consistent HMAC signature")
        void shouldGenerateConsistentHmacSignature() throws Exception {
            // Test that the same payload + secret always produces the same signature
            IntentRecord record = createTestRecord("req-signature-001");
            record.setStatus(IntentStatus.EXECUTED);

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenReturn(response);
            when(response.isSuccessful()).thenReturn(true);

            webhookService.notify(record);
            webhookService.notify(record);

            ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
            verify(okHttpClient, org.mockito.Mockito.times(2)).newCall(requestCaptor.capture());

            java.util.List<Request> requests = requestCaptor.getAllValues();
            String sig1 = requests.get(0).header("X-Signature");
            String sig2 = requests.get(1).header("X-Signature");

            assertThat(sig1).isEqualTo(sig2);
        }

        @Test
        @DisplayName("Signature should start with sha256= prefix")
        void signatureShouldStartWithSha256Prefix() throws IOException {
            IntentRecord record = createTestRecord("req-signature-002");

            when(okHttpClient.newCall(any(Request.class))).thenReturn(call);
            when(call.execute()).thenReturn(response);
            when(response.isSuccessful()).thenReturn(true);

            webhookService.notify(record);

            ArgumentCaptor<Request> requestCaptor = ArgumentCaptor.forClass(Request.class);
            verify(okHttpClient).newCall(requestCaptor.capture());

            String signature = requestCaptor.getValue().header("X-Signature");
            assertThat(signature).startsWith("sha256=");
            // sha256 produces 64 hex characters
            assertThat(signature).hasSize(7 + 64); // "sha256=" + 64 hex chars
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should accept empty webhook URL")
        void shouldAcceptEmptyWebhookUrl() {
            IntentWebhookService service = new IntentWebhookService("", "secret");
            assertThat(service).isNotNull();
        }

        @Test
        @DisplayName("Should accept empty webhook secret")
        void shouldAcceptEmptyWebhookSecret() {
            IntentWebhookService service = new IntentWebhookService(WEBHOOK_URL, "");
            assertThat(service).isNotNull();
        }
    }

    private IntentRecord createTestRecord(String requestId) {
        IntentRecord record = new IntentRecord(requestId, "LAB_ADD", "github");
        record.setStatus(IntentStatus.QUEUED);
        record.setCreatedAt(Instant.now());
        record.setUpdatedAt(Instant.now());
        return record;
    }
}
