package decentralabs.blockchain.notification;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("MailSenderFactory Tests")
class MailSenderFactoryTest {

    @Mock
    private NotificationConfigService notificationConfigService;

    private ObjectMapper objectMapper;
    private MailSenderFactory factory;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        factory = new MailSenderFactory(notificationConfigService, objectMapper);
    }

    @Nested
    @DisplayName("resolve() Tests")
    class ResolveTests {

        @Test
        @DisplayName("Should return NoopMailSenderAdapter for NOOP driver")
        void shouldReturnNoopForNoopDriver() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.NOOP);
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(NoopMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should return NoopMailSenderAdapter when driver is null")
        void shouldReturnNoopForNullDriver() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(null);
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(NoopMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should return SmtpMailSenderAdapter for SMTP driver")
        void shouldReturnSmtpForSmtpDriver() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.SMTP);
            mail.setFrom("test@example.com");
            
            NotificationProperties.Smtp smtp = new NotificationProperties.Smtp();
            smtp.setHost("smtp.example.com");
            smtp.setPort(587);
            mail.setSmtp(smtp);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(SmtpMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should return GraphMailSenderAdapter for GRAPH driver with valid config")
        void shouldReturnGraphForGraphDriverWithValidConfig() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.GRAPH);
            mail.setFrom("sender@example.com");
            
            NotificationProperties.Graph graph = new NotificationProperties.Graph();
            graph.setTenantId("tenant-123");
            graph.setClientId("client-456");
            graph.setClientSecret("secret-789");
            graph.setFrom("graph@example.com");
            mail.setGraph(graph);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(GraphMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should fallback to NoopMailSenderAdapter for GRAPH without tenant")
        void shouldFallbackToNoopForGraphWithoutTenant() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.GRAPH);
            
            NotificationProperties.Graph graph = new NotificationProperties.Graph();
            graph.setTenantId(null); // Missing tenant
            graph.setClientId("client-456");
            graph.setClientSecret("secret-789");
            mail.setGraph(graph);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(NoopMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should fallback to NoopMailSenderAdapter for GRAPH without clientId")
        void shouldFallbackToNoopForGraphWithoutClientId() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.GRAPH);
            
            NotificationProperties.Graph graph = new NotificationProperties.Graph();
            graph.setTenantId("tenant-123");
            graph.setClientId(null); // Missing clientId
            graph.setClientSecret("secret-789");
            mail.setGraph(graph);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(NoopMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should fallback to NoopMailSenderAdapter for GRAPH without clientSecret")
        void shouldFallbackToNoopForGraphWithoutClientSecret() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.GRAPH);
            
            NotificationProperties.Graph graph = new NotificationProperties.Graph();
            graph.setTenantId("tenant-123");
            graph.setClientId("client-456");
            graph.setClientSecret(null); // Missing secret
            mail.setGraph(graph);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(NoopMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should fallback to NoopMailSenderAdapter for GRAPH without from address")
        void shouldFallbackToNoopForGraphWithoutFrom() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.GRAPH);
            mail.setFrom(null); // No global from
            
            NotificationProperties.Graph graph = new NotificationProperties.Graph();
            graph.setTenantId("tenant-123");
            graph.setClientId("client-456");
            graph.setClientSecret("secret-789");
            graph.setFrom(null); // No graph-specific from either
            mail.setGraph(graph);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(NoopMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should use global from when graph from is blank")
        void shouldUseGlobalFromWhenGraphFromIsBlank() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.GRAPH);
            mail.setFrom("global@example.com"); // Global from set
            
            NotificationProperties.Graph graph = new NotificationProperties.Graph();
            graph.setTenantId("tenant-123");
            graph.setClientId("client-456");
            graph.setClientSecret("secret-789");
            graph.setFrom(""); // Blank graph from
            mail.setGraph(graph);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(GraphMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should fallback to NoopMailSenderAdapter for GRAPH with null graph config")
        void shouldFallbackToNoopForNullGraphConfig() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.GRAPH);
            mail.setGraph(null);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(NoopMailSenderAdapter.class, adapter);
        }

        @Test
        @DisplayName("Should handle blank strings in Graph config")
        void shouldHandleBlankStringsInGraphConfig() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setDriver(MailDriver.GRAPH);
            
            NotificationProperties.Graph graph = new NotificationProperties.Graph();
            graph.setTenantId("   "); // Blank
            graph.setClientId("client-456");
            graph.setClientSecret("secret-789");
            graph.setFrom("from@example.com");
            mail.setGraph(graph);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            MailSenderAdapter adapter = factory.resolve();

            assertInstanceOf(NoopMailSenderAdapter.class, adapter);
        }
    }
}
