package decentralabs.blockchain.notification;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

@Slf4j
public class GraphMailSenderAdapter implements MailSenderAdapter {

    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");
    private static final String GRAPH_SCOPE = "https://graph.microsoft.com/.default";

    private final NotificationProperties.Mail mailProps;
    private final ClientSecretCredential credential;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;

    public GraphMailSenderAdapter(
        NotificationProperties.Mail mailProps,
        OkHttpClient httpClient,
        ObjectMapper objectMapper
    ) {
        this.mailProps = mailProps;
        this.httpClient = httpClient != null ? httpClient : new OkHttpClient();
        this.objectMapper = objectMapper;
        NotificationProperties.Graph graph = mailProps.getGraph();
        this.credential = new ClientSecretCredentialBuilder()
            .tenantId(graph.getTenantId())
            .clientId(graph.getClientId())
            .clientSecret(graph.getClientSecret())
            .build();
    }

    @Override
    public void send(NotificationMessage message) {
        if (!isConfigured()) {
            log.warn("Graph mail driver not fully configured. Skipping email notification.");
            return;
        }
        if (message.recipients() == null || message.recipients().isEmpty()) {
            log.warn("No recipients provided. Skipping email notification.");
            return;
        }

        try {
            AccessToken token = credential
                .getToken(new TokenRequestContext().addScopes(GRAPH_SCOPE))
                .block(Duration.ofSeconds(10));

            if (token == null || token.isExpired()) {
                log.error("Could not obtain access token for Microsoft Graph.");
                return;
            }

            Map<String, Object> payload = buildPayload(message);
            String json = objectMapper.writeValueAsString(payload);

            RequestBody body = RequestBody.create(json, JSON_MEDIA_TYPE);
            String from = resolveFromAddress();
            Request request = new Request.Builder()
                .url("https://graph.microsoft.com/v1.0/users/" + from + "/sendMail")
                .addHeader("Authorization", "Bearer " + token.getToken())
                .addHeader("Content-Type", "application/json")
                .post(body)
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    log.error("Graph sendMail failed ({}): {}", response.code(), response.message());
                } else {
                    log.info("Sent reservation notification via Graph to {}", message.recipients());
                }
            }
        } catch (IOException e) {
            log.error("Failed to send reservation notification via Graph: {}", e.getMessage(), e);
        }
    }

    private Map<String, Object> buildPayload(NotificationMessage message) {
        Map<String, Object> email = new HashMap<>();
        email.put("subject", message.subject());

        String content = message.htmlBody() != null ? message.htmlBody() : message.textBody();
        email.put("body", Map.of(
            "contentType", "HTML",
            "content", content
        ));

        email.put("toRecipients", toRecipients(message.recipients()));

        if (message.icsContent() != null && !message.icsContent().isBlank()) {
            Map<String, Object> attachment = new HashMap<>();
            attachment.put("@odata.type", "#microsoft.graph.fileAttachment");
            attachment.put("name", message.icsFileName() != null ? message.icsFileName() : "reservation.ics");
            attachment.put("contentType", "text/calendar");
            attachment.put("contentBytes", Base64.getEncoder().encodeToString(
                message.icsContent().getBytes(StandardCharsets.UTF_8)
            ));
            email.put("attachments", List.of(attachment));
        }

        return Map.of(
            "message", email,
            "saveToSentItems", false
        );
    }

    private List<Map<String, Object>> toRecipients(List<String> recipients) {
        return recipients.stream()
            .filter(Objects::nonNull)
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .map(address -> {
                Map<String, Object> recipient = new HashMap<>();
                recipient.put("emailAddress", Map.of("address", address));
                return recipient;
            })
            .collect(Collectors.toList());
    }

    private boolean isConfigured() {
        NotificationProperties.Graph graph = mailProps.getGraph();
        return graph.getTenantId() != null && !graph.getTenantId().isBlank()
            && graph.getClientId() != null && !graph.getClientId().isBlank()
            && graph.getClientSecret() != null && !graph.getClientSecret().isBlank()
            && resolveFromAddress() != null;
    }

    private String resolveFromAddress() {
        String from = mailProps.getGraph().getFrom();
        if (from == null || from.isBlank()) {
            from = mailProps.getFrom();
        }
        if (from == null || from.isBlank()) {
            return null;
        }
        return URLEncoder.encode(from, StandardCharsets.UTF_8);
    }
}
