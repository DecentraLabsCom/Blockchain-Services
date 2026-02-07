package decentralabs.blockchain.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;
import java.time.Duration;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class MailSenderFactory {

    private final NotificationConfigService notificationConfigService;
    private final ObjectMapper objectMapper;

    private final OkHttpClient okHttpClient = new OkHttpClient.Builder()
        .connectTimeout(Duration.ofSeconds(10))
        .readTimeout(Duration.ofSeconds(30))
        .writeTimeout(Duration.ofSeconds(30))
        .callTimeout(Duration.ofSeconds(30))
        .addInterceptor(new HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BASIC))
        .build();

    public MailSenderAdapter resolve() {
        NotificationProperties.Mail mail = notificationConfigService.getMailConfig();
        MailDriver driver = mail.getDriver() != null ? mail.getDriver() : MailDriver.NOOP;
        return switch (driver) {
            case SMTP -> new SmtpMailSenderAdapter(mail);
            case GRAPH -> {
                if (isGraphConfigured(mail)) {
                    yield new GraphMailSenderAdapter(mail, okHttpClient, objectMapper);
                }
                log.warn("Graph driver selected but credentials are missing. Falling back to noop.");
                yield new NoopMailSenderAdapter();
            }
            case NOOP -> new NoopMailSenderAdapter();
        };
    }

    private boolean isGraphConfigured(NotificationProperties.Mail mail) {
        NotificationProperties.Graph graph = mail.getGraph();
        return graph != null
            && graph.getTenantId() != null && !graph.getTenantId().isBlank()
            && graph.getClientId() != null && !graph.getClientId().isBlank()
            && graph.getClientSecret() != null && !graph.getClientSecret().isBlank()
            && ((graph.getFrom() != null && !graph.getFrom().isBlank())
                || (mail.getFrom() != null && !mail.getFrom().isBlank()));
    }
}
