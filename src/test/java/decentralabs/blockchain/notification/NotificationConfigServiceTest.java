package decentralabs.blockchain.notification;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("NotificationConfigService Tests")
class NotificationConfigServiceTest {

    private NotificationProperties properties;
    private ObjectMapper objectMapper;
    private NotificationConfigService service;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        properties = new NotificationProperties();
        properties.setConfigFile(tempDir.resolve("notifications-config.json").toString());
        objectMapper = new ObjectMapper();
        service = new NotificationConfigService(properties, objectMapper);
    }

    @Nested
    @DisplayName("getMailConfig Tests")
    class GetMailConfigTests {

        @Test
        @DisplayName("Should return mail config")
        void shouldReturnMailConfig() {
            NotificationProperties.Mail mail = service.getMailConfig();
            
            assertNotNull(mail);
        }

        @Test
        @DisplayName("Should return default values")
        void shouldReturnDefaultValues() {
            NotificationProperties.Mail mail = service.getMailConfig();
            
            assertTrue(mail.isEnabled());
            assertEquals(MailDriver.NOOP, mail.getDriver());
        }
    }

    @Nested
    @DisplayName("updateMailConfig Tests")
    class UpdateMailConfigTests {

        @Test
        @DisplayName("Should update enabled flag")
        void shouldUpdateEnabled() {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                false, null, null, null, null, null, null, null
            );

            service.updateMailConfig(request);

            assertFalse(service.getMailConfig().isEnabled());
        }

        @Test
        @DisplayName("Should update driver")
        void shouldUpdateDriver() {
            // When switching to SMTP, need to have valid SMTP config to pass validation
            properties.getMail().getSmtp().setHost("smtp.example.com");
            properties.getMail().getSmtp().setUsername("user");
            properties.getMail().getSmtp().setPassword("pass");
            
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                null, MailDriver.SMTP, null, null, null, null, null, null
            );

            service.updateMailConfig(request);

            assertEquals(MailDriver.SMTP, service.getMailConfig().getDriver());
        }

        @Test
        @DisplayName("Should update from address")
        void shouldUpdateFromAddress() {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                null, null, "new@email.com", "New Name", null, null, null, null
            );

            service.updateMailConfig(request);

            assertEquals("new@email.com", service.getMailConfig().getFrom());
            assertEquals("New Name", service.getMailConfig().getFromName());
        }

        @Test
        @DisplayName("Should update recipients")
        void shouldUpdateRecipients() {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                null, null, null, null, List.of("admin@test.com", "ops@test.com"), null, null, null
            );

            service.updateMailConfig(request);

            assertEquals(2, service.getMailConfig().getDefaultTo().size());
            assertTrue(service.getMailConfig().getDefaultTo().contains("admin@test.com"));
        }

        @Test
        @DisplayName("Should normalize recipients (trim and filter empty)")
        void shouldNormalizeRecipients() {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                null, null, null, null, 
                List.of("  admin@test.com  ", "", "  ", "ops@test.com"), 
                null, null, null
            );

            service.updateMailConfig(request);

            List<String> recipients = service.getMailConfig().getDefaultTo();
            assertEquals(2, recipients.size());
            assertEquals("admin@test.com", recipients.get(0));
        }

        @Test
        @DisplayName("Should update timezone")
        void shouldUpdateTimezone() {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                null, null, null, null, null, "Europe/Madrid", null, null
            );

            service.updateMailConfig(request);

            assertEquals("Europe/Madrid", service.getMailConfig().getTimezone());
        }

        @Test
        @DisplayName("Should update SMTP settings")
        void shouldUpdateSmtpSettings() {
            NotificationUpdateRequest.Smtp smtp = new NotificationUpdateRequest.Smtp(
                "smtp.test.com", 465, "user", "pass", true, true, 5000
            );
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                null, null, null, null, null, null, smtp, null
            );

            service.updateMailConfig(request);

            NotificationProperties.Smtp config = service.getMailConfig().getSmtp();
            assertEquals("smtp.test.com", config.getHost());
            assertEquals(465, config.getPort());
            assertEquals("user", config.getUsername());
        }

        @Test
        @DisplayName("Should update Graph settings")
        void shouldUpdateGraphSettings() {
            NotificationUpdateRequest.Graph graph = new NotificationUpdateRequest.Graph(
                "tenant-123", "client-456", "secret-789", "graph@test.com"
            );
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                null, null, null, null, null, null, null, graph
            );

            service.updateMailConfig(request);

            NotificationProperties.Graph config = service.getMailConfig().getGraph();
            assertEquals("tenant-123", config.getTenantId());
            assertEquals("client-456", config.getClientId());
        }

        @Test
        @DisplayName("Should persist config to file")
        void shouldPersistConfigToFile() throws IOException {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true, MailDriver.NOOP, "test@test.com", null, null, null, null, null
            );

            service.updateMailConfig(request);

            Path configPath = Path.of(properties.getConfigFile());
            assertTrue(Files.exists(configPath));
        }
    }

    @Nested
    @DisplayName("validateUpdate Tests")
    class ValidateUpdateTests {

        @Test
        @DisplayName("Should return no errors for NOOP driver")
        void shouldReturnNoErrorsForNoop() {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true, MailDriver.NOOP, null, null, null, null, null, null
            );

            List<String> errors = service.validateUpdate(request);

            assertTrue(errors.isEmpty());
        }

        @Test
        @DisplayName("Should return no errors when disabled")
        void shouldReturnNoErrorsWhenDisabled() {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                false, MailDriver.SMTP, null, null, null, null, null, null
            );

            List<String> errors = service.validateUpdate(request);

            assertTrue(errors.isEmpty());
        }

        @Test
        @DisplayName("Should return errors for SMTP without host")
        void shouldReturnErrorsForSmtpWithoutHost() {
            properties.getMail().setEnabled(true);
            properties.getMail().setDriver(MailDriver.SMTP);
            properties.getMail().getSmtp().setHost(null);
            
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true, MailDriver.SMTP, null, null, null, null, null, null
            );

            List<String> errors = service.validateUpdate(request);

            assertTrue(errors.stream().anyMatch(e -> e.contains("host")));
        }

        @Test
        @DisplayName("Should return errors for SMTP auth without credentials")
        void shouldReturnErrorsForSmtpAuthWithoutCredentials() {
            properties.getMail().setEnabled(true);
            properties.getMail().setDriver(MailDriver.SMTP);
            properties.getMail().getSmtp().setHost("smtp.test.com");
            properties.getMail().getSmtp().setAuth(true);
            properties.getMail().getSmtp().setUsername(null);
            properties.getMail().getSmtp().setPassword(null);
            
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true, MailDriver.SMTP, null, null, null, null, null, null
            );

            List<String> errors = service.validateUpdate(request);

            assertTrue(errors.stream().anyMatch(e -> e.contains("username")));
            assertTrue(errors.stream().anyMatch(e -> e.contains("password")));
        }

        @Test
        @DisplayName("Should return errors for Graph without tenant")
        void shouldReturnErrorsForGraphWithoutTenant() {
            properties.getMail().setEnabled(true);
            properties.getMail().setDriver(MailDriver.GRAPH);
            properties.getMail().getGraph().setTenantId(null);
            
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true, MailDriver.GRAPH, null, null, null, null, null, null
            );

            List<String> errors = service.validateUpdate(request);

            assertTrue(errors.stream().anyMatch(e -> e.contains("tenantId")));
        }

        @Test
        @DisplayName("Should return errors for Graph without from address")
        void shouldReturnErrorsForGraphWithoutFrom() {
            properties.getMail().setEnabled(true);
            properties.getMail().setDriver(MailDriver.GRAPH);
            properties.getMail().getGraph().setTenantId("tenant");
            properties.getMail().getGraph().setClientId("client");
            properties.getMail().getGraph().setClientSecret("secret");
            properties.getMail().getGraph().setFrom(null);
            properties.getMail().setFrom(null);
            
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true, MailDriver.GRAPH, null, null, null, null, null, null
            );

            List<String> errors = service.validateUpdate(request);

            assertTrue(errors.stream().anyMatch(e -> e.contains("from")));
        }
    }

    @Nested
    @DisplayName("loadFromDiskIfPresent Tests")
    class LoadFromDiskTests {

        @Test
        @DisplayName("Should load config from existing file")
        void shouldLoadConfigFromExistingFile() throws IOException {
            // Create a config file
            NotificationProperties.Mail savedMail = new NotificationProperties.Mail();
            savedMail.setEnabled(false);
            savedMail.setDriver(MailDriver.SMTP);
            savedMail.setFrom("loaded@test.com");
            
            Path configPath = Path.of(properties.getConfigFile());
            Files.createDirectories(configPath.getParent());
            objectMapper.writeValue(configPath.toFile(), savedMail);

            service.loadFromDiskIfPresent();

            assertFalse(service.getMailConfig().isEnabled());
            assertEquals(MailDriver.SMTP, service.getMailConfig().getDriver());
            assertEquals("loaded@test.com", service.getMailConfig().getFrom());
        }

        @Test
        @DisplayName("Should not fail when file doesn't exist")
        void shouldNotFailWhenFileDoesntExist() {
            properties.setConfigFile(tempDir.resolve("nonexistent.json").toString());

            assertDoesNotThrow(() -> service.loadFromDiskIfPresent());
        }

        @Test
        @DisplayName("Should not fail on invalid JSON")
        void shouldNotFailOnInvalidJson() throws IOException {
            Path configPath = Path.of(properties.getConfigFile());
            Files.createDirectories(configPath.getParent());
            Files.writeString(configPath, "invalid json {{{");

            assertDoesNotThrow(() -> service.loadFromDiskIfPresent());
        }
    }

    @Nested
    @DisplayName("getPublicConfig Tests")
    class GetPublicConfigTests {

        @Test
        @DisplayName("Should return public config without secrets")
        void shouldReturnPublicConfigWithoutSecrets() {
            properties.getMail().setEnabled(true);
            properties.getMail().setFrom("test@test.com");
            properties.getMail().setFromName("Test Sender");
            properties.getMail().setTimezone("UTC");
            properties.getMail().setDriver(MailDriver.SMTP);
            
            // SMTP config with a password (secret)
            properties.getMail().getSmtp().setHost("smtp.test.com");
            properties.getMail().getSmtp().setPort(587);
            properties.getMail().getSmtp().setUsername("user@test.com");
            properties.getMail().getSmtp().setPassword("secret-password");
            
            // Graph config with secrets
            properties.getMail().getGraph().setTenantId("tenant-123");
            properties.getMail().getGraph().setClientId("client-456");
            properties.getMail().getGraph().setClientSecret("secret-client-secret");
            properties.getMail().getGraph().setFrom("graph@test.com");

            Map<String, Object> config = service.getPublicConfig();

            // Should have public fields
            assertEquals(true, config.get("enabled"));
            assertEquals("test@test.com", config.get("from"));
            assertEquals(MailDriver.SMTP, config.get("driver"));
            
            // SMTP should not include password
            @SuppressWarnings("unchecked")
            Map<String, Object> smtp = (Map<String, Object>) config.get("smtp");
            assertEquals("smtp.test.com", smtp.get("host"));
            assertEquals(587, smtp.get("port"));
            assertEquals("user@test.com", smtp.get("username"));
            assertFalse(smtp.containsKey("password"));
            
            // Graph should not include clientSecret
            @SuppressWarnings("unchecked")
            Map<String, Object> graph = (Map<String, Object>) config.get("graph");
            assertEquals("tenant-123", graph.get("tenantId"));
            assertEquals("client-456", graph.get("clientId"));
            assertFalse(graph.containsKey("clientSecret"));
        }
    }

    @Nested
    @DisplayName("validateMailConfig Tests")
    class ValidateMailConfigTests {

        @Test
        @DisplayName("Should validate current config")
        void shouldValidateCurrentConfig() {
            properties.getMail().setEnabled(false);
            
            List<String> errors = service.validateMailConfig();
            
            assertTrue(errors.isEmpty());
        }

        @Test
        @DisplayName("Should return errors for invalid SMTP port")
        void shouldReturnErrorsForInvalidSmtpPort() {
            properties.getMail().setEnabled(true);
            properties.getMail().setDriver(MailDriver.SMTP);
            properties.getMail().getSmtp().setHost("smtp.test.com");
            properties.getMail().getSmtp().setPort(0);
            properties.getMail().getSmtp().setAuth(false);
            
            List<String> errors = service.validateMailConfig();
            
            assertTrue(errors.stream().anyMatch(e -> e.contains("port")));
        }
    }
}
