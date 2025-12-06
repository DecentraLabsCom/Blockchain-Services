package decentralabs.blockchain.service.intent;

import java.nio.charset.StandardCharsets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class IntentWebhookService {

    private final OkHttpClient client = new OkHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String webhookUrl;
    private final String webhookSecret;

    public IntentWebhookService(
        @Value("${intent.webhook.url:}") String webhookUrl,
        @Value("${intent.webhook.secret:}") String webhookSecret
    ) {
        this.webhookUrl = webhookUrl;
        this.webhookSecret = webhookSecret;
    }

    public void notify(IntentRecord record) {
        if (webhookUrl == null || webhookUrl.isBlank()) {
            return;
        }
        try {
            String payload = mapper.writeValueAsString(WebhookPayload.from(record));
            RequestBody body = RequestBody.create(payload, MediaType.parse("application/json"));
            Request.Builder builder = new Request.Builder().url(webhookUrl).post(body);
            if (webhookSecret != null && !webhookSecret.isBlank()) {
                builder.addHeader("X-Signature", sign(payload, webhookSecret));
            }
            Response response = client.newCall(builder.build()).execute();
            if (!response.isSuccessful()) {
                log.warn("Webhook for intent {} responded with {}", record.getRequestId(), response.code());
            }
        } catch (Exception e) {
            log.warn("Unable to send webhook for {}: {}", record.getRequestId(), e.getMessage());
        }
    }

    private String sign(String payload, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] signature = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder("sha256=");
        for (byte b : signature) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private record WebhookPayload(
        String requestId,
        String status,
        String txHash,
        Long blockNumber,
        String labId,
        String reservationKey,
        String reason
    ) {
        static WebhookPayload from(IntentRecord record) {
            return new WebhookPayload(
                record.getRequestId(),
                record.getStatus().getWireValue(),
                record.getTxHash(),
                record.getBlockNumber(),
                record.getLabId(),
                record.getReservationKey(),
                record.getError() != null ? record.getError() : record.getReason()
            );
        }
    }
}
