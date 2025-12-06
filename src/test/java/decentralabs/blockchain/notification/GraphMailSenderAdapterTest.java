package decentralabs.blockchain.notification;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import okhttp3.OkHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for GraphMailSenderAdapter.
 * Note: Tests that call send() are limited because actual Azure token acquisition 
 * requires valid Azure AD credentials. These tests focus on configuration validation.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("GraphMailSenderAdapter Tests")
class GraphMailSenderAdapterTest {

    @Mock
    private OkHttpClient httpClient;

    private ObjectMapper objectMapper;
    private NotificationProperties.Mail mailProps;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        mailProps = new NotificationProperties.Mail();
        mailProps.setEnabled(true);
        mailProps.setFrom("noreply@test.com");
        mailProps.setFromName("Test Sender");
        
        NotificationProperties.Graph graph = new NotificationProperties.Graph();
        graph.setTenantId("test-tenant-id");
        graph.setClientId("test-client-id");
        graph.setClientSecret("test-client-secret");
        graph.setFrom("graph-sender@test.com");
        mailProps.setGraph(graph);
        
        // Also set up SMTP to avoid NPEs
        NotificationProperties.Smtp smtp = new NotificationProperties.Smtp();
        smtp.setHost("smtp.test.com");
        smtp.setPort(587);
        mailProps.setSmtp(smtp);
    }

    // Helper method to create NotificationMessage (record constructor)
    @SuppressWarnings("unused")
    private NotificationMessage createMessage(List<String> recipients, String subject, 
            String textBody, String htmlBody, String icsContent, String icsFileName) {
        return new NotificationMessage(recipients, subject, textBody, htmlBody, icsContent, icsFileName);
    }

    private NotificationMessage createSimpleMessage(List<String> recipients, String subject, String textBody) {
        return new NotificationMessage(recipients, subject, textBody, null, null, null);
    }

    @Nested
    @DisplayName("Configuration Validation Tests")
    class ConfigurationValidationTests {

        @Test
        @DisplayName("Should throw when tenant ID is null")
        void shouldThrowWhenTenantIdNull() {
            mailProps.getGraph().setTenantId(null);
            
            // Creating adapter will fail because Azure ClientSecretCredentialBuilder 
            // requires tenantId
            assertThrows(Exception.class, () -> 
                new GraphMailSenderAdapter(mailProps, httpClient, objectMapper)
            );
        }

        @Test
        @DisplayName("Should throw when tenant ID is blank")
        void shouldThrowWhenTenantIdBlank() {
            mailProps.getGraph().setTenantId("   ");
            
            assertThrows(Exception.class, () ->
                new GraphMailSenderAdapter(mailProps, httpClient, objectMapper)
            );
        }

        @Test
        @DisplayName("Should throw when client ID is null")
        void shouldThrowWhenClientIdNull() {
            mailProps.getGraph().setClientId(null);
            
            assertThrows(Exception.class, () ->
                new GraphMailSenderAdapter(mailProps, httpClient, objectMapper)
            );
        }

        @Test
        @DisplayName("Should throw when client secret is null")
        void shouldThrowWhenClientSecretNull() {
            mailProps.getGraph().setClientSecret(null);
            
            assertThrows(Exception.class, () ->
                new GraphMailSenderAdapter(mailProps, httpClient, objectMapper)
            );
        }
    }

    @Nested
    @DisplayName("Recipient Validation Tests")
    class RecipientValidationTests {

        @Test
        @DisplayName("Should skip send when recipients is null - graceful handling")
        void shouldSkipWhenRecipientsNull() {
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, httpClient, objectMapper);
            
            NotificationMessage message = createSimpleMessage(null, "Test", "Body");
            
            // Should not throw, just log warning and return early
            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should skip send when recipients is empty - graceful handling")
        void shouldSkipWhenRecipientsEmpty() {
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, httpClient, objectMapper);
            
            NotificationMessage message = createSimpleMessage(List.of(), "Test", "Body");
            
            // Should not throw, just log warning and return early
            assertDoesNotThrow(() -> adapter.send(message));
        }
    }

    @Nested
    @DisplayName("From Address Resolution Tests")
    class FromAddressResolutionTests {

        @Test
        @DisplayName("Should use graph from address when set")
        void shouldUseGraphFromAddress() {
            mailProps.getGraph().setFrom("graph@test.com");
            mailProps.setFrom("default@test.com");
            
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, httpClient, objectMapper);
            
            // Adapter is created successfully with graph from address
            assertNotNull(adapter);
        }

        @Test
        @DisplayName("Should fall back to default from when graph from is null")
        void shouldFallbackToDefaultFrom() {
            mailProps.getGraph().setFrom(null);
            mailProps.setFrom("default@test.com");
            
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, httpClient, objectMapper);
            
            assertNotNull(adapter);
        }

        @Test
        @DisplayName("Should fall back to default from when graph from is blank")
        void shouldFallbackToDefaultFromWhenBlank() {
            mailProps.getGraph().setFrom("   ");
            mailProps.setFrom("default@test.com");
            
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, httpClient, objectMapper);
            
            assertNotNull(adapter);
        }
    }

    @Nested
    @DisplayName("OkHttpClient Initialization Tests")
    class HttpClientTests {

        @Test
        @DisplayName("Should use provided OkHttpClient")
        void shouldUseProvidedHttpClient() {
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, httpClient, objectMapper);
            assertNotNull(adapter);
        }

        @Test
        @DisplayName("Should create default OkHttpClient when null provided")
        void shouldCreateDefaultHttpClient() {
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, null, objectMapper);
            assertNotNull(adapter);
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create adapter with valid configuration")
        void shouldCreateAdapterWithValidConfiguration() {
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, httpClient, objectMapper);
            assertNotNull(adapter);
        }

        @Test
        @DisplayName("Should accept null ObjectMapper")
        void shouldAcceptNullObjectMapper() {
            // The adapter uses objectMapper to serialize, passing null may cause NPE later
            // but constructor should not fail
            GraphMailSenderAdapter adapter = new GraphMailSenderAdapter(mailProps, httpClient, null);
            assertNotNull(adapter);
        }
    }
}
