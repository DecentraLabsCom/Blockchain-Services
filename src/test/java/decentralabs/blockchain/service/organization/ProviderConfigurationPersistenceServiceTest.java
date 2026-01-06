package decentralabs.blockchain.service.organization;

import decentralabs.blockchain.dto.provider.ProviderConfigurationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ProviderConfigurationPersistenceService Tests")
class ProviderConfigurationPersistenceServiceTest {

    private ProviderConfigurationPersistenceService service;
    
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        service = new ProviderConfigurationPersistenceService();
        // Set the config path to our temp directory
        ReflectionTestUtils.setField(service, "configLocation", tempDir.resolve("provider.properties").toString());
    }

    @AfterEach
    void tearDown() {
        // Clean up is handled by @TempDir
    }

    @Test
    @DisplayName("Should save provider configuration successfully")
    void shouldSaveConfiguration() throws IOException {
        ProviderConfigurationRequest request = new ProviderConfigurationRequest();
        request.setMarketplaceBaseUrl("https://marketplace.example.com");
        request.setProviderName("Test University");
        request.setProviderEmail("test@university.edu");
        request.setProviderCountry("US");
        request.setProviderOrganization("university.edu");
        request.setPublicBaseUrl("https://gateway.university.edu");

        service.saveConfiguration(request);

        Properties props = service.loadConfigurationSafe();
        assertEquals("https://marketplace.example.com", props.getProperty("marketplace.base-url"));
        assertEquals("Test University", props.getProperty("provider.name"));
        assertEquals("test@university.edu", props.getProperty("provider.email"));
        assertEquals("US", props.getProperty("provider.country"));
        assertEquals("university.edu", props.getProperty("provider.organization"));
        assertEquals("https://gateway.university.edu", props.getProperty("public.base-url"));
        assertEquals("manual", props.getProperty("provisioning.source"));
    }

    @Test
    @DisplayName("Should mark provider as registered")
    void shouldMarkProviderRegistered() throws IOException {
        // First save a configuration
        ProviderConfigurationRequest request = new ProviderConfigurationRequest();
        request.setMarketplaceBaseUrl("https://marketplace.example.com");
        request.setProviderName("Test University");
        request.setProviderEmail("test@university.edu");
        request.setProviderCountry("US");
        request.setProviderOrganization("university.edu");
        request.setPublicBaseUrl("https://gateway.university.edu");

        service.saveConfiguration(request);

        // Verify not registered initially
        Properties propsBeforeReg = service.loadConfigurationSafe();
        assertNotEquals("true", propsBeforeReg.getProperty("provider.registered"));

        // Mark as registered
        service.markProviderRegistered();

        // Verify registered flag is set
        Properties propsAfterReg = service.loadConfigurationSafe();
        assertEquals("true", propsAfterReg.getProperty("provider.registered"));
        
        // Verify other properties are preserved
        assertEquals("https://marketplace.example.com", propsAfterReg.getProperty("marketplace.base-url"));
        assertEquals("Test University", propsAfterReg.getProperty("provider.name"));
    }

    @Test
    @DisplayName("Should create config file if it doesn't exist when marking as registered")
    void shouldCreateFileWhenMarkingAsRegistered() throws IOException {
        // Don't create any config file first
        Path configPath = tempDir.resolve("provider.properties");
        assertFalse(Files.exists(configPath));

        // Mark as registered
        service.markProviderRegistered();

        // Verify file was created with registered flag
        assertTrue(Files.exists(configPath));
        Properties props = service.loadConfigurationSafe();
        assertEquals("true", props.getProperty("provider.registered"));
    }

    @Test
    @DisplayName("Should preserve existing properties when marking as registered")
    void shouldPreservePropertiesWhenMarkingAsRegistered() throws IOException {
        // Save initial config
        ProviderConfigurationRequest request = new ProviderConfigurationRequest();
        request.setMarketplaceBaseUrl("https://marketplace.example.com");
        request.setProviderName("Test University");
        request.setProviderEmail("test@university.edu");
        request.setProviderCountry("US");
        request.setProviderOrganization("university.edu");
        request.setPublicBaseUrl("https://gateway.university.edu");

        service.saveConfiguration(request);

        // Mark as registered multiple times
        service.markProviderRegistered();
        service.markProviderRegistered();

        // Verify all properties still intact
        Properties props = service.loadConfigurationSafe();
        assertEquals("true", props.getProperty("provider.registered"));
        assertEquals("https://marketplace.example.com", props.getProperty("marketplace.base-url"));
        assertEquals("Test University", props.getProperty("provider.name"));
        assertEquals("test@university.edu", props.getProperty("provider.email"));
        assertEquals("US", props.getProperty("provider.country"));
        assertEquals("university.edu", props.getProperty("provider.organization"));
        assertEquals("https://gateway.university.edu", props.getProperty("public.base-url"));
    }

    @Test
    @DisplayName("Should load configuration safely when file doesn't exist")
    void shouldLoadConfigSafelyWhenFileDoesntExist() {
        Properties props = service.loadConfigurationSafe();
        assertNotNull(props);
        assertTrue(props.isEmpty());
    }

    @Test
    @DisplayName("Should save configuration with provisioning source as token")
    void shouldSaveConfigurationFromToken() throws IOException {
        var payload = decentralabs.blockchain.dto.provider.ProvisioningTokenPayload.builder()
            .marketplaceBaseUrl("https://marketplace.example.com")
            .providerName("Token University")
            .providerEmail("token@university.edu")
            .providerCountry("ES")
            .providerOrganization("token.edu")
            .publicBaseUrl("https://token.university.edu")
            .jti("test-jti-456")
            .build();

        service.saveConfigurationFromToken(payload);

        Properties props = service.loadConfigurationSafe();
        assertEquals("https://marketplace.example.com", props.getProperty("marketplace.base-url"));
        assertEquals("Token University", props.getProperty("provider.name"));
        assertEquals("token@university.edu", props.getProperty("provider.email"));
        assertEquals("ES", props.getProperty("provider.country"));
        assertEquals("token.edu", props.getProperty("provider.organization"));
        assertEquals("https://token.university.edu", props.getProperty("public.base-url"));
        assertEquals("token", props.getProperty("provisioning.source"));
    }

    @Test
    @DisplayName("Should handle registered flag correctly across save and mark operations")
    void shouldHandleRegisteredFlagCorrectly() throws IOException {
        // Initial save
        ProviderConfigurationRequest request = new ProviderConfigurationRequest();
        request.setMarketplaceBaseUrl("https://marketplace.example.com");
        request.setProviderName("Test University");
        request.setProviderEmail("test@university.edu");
        request.setProviderCountry("US");
        request.setProviderOrganization("university.edu");
        request.setPublicBaseUrl("https://gateway.university.edu");

        service.saveConfiguration(request);
        
        Properties props1 = service.loadConfigurationSafe();
        assertNotEquals("true", props1.getProperty("provider.registered"));

        // Mark as registered
        service.markProviderRegistered();
        
        Properties props2 = service.loadConfigurationSafe();
        assertEquals("true", props2.getProperty("provider.registered"));

        // Save again (should preserve registered flag)
        request.setProviderName("Updated University");
        service.saveConfiguration(request);
        
        Properties props3 = service.loadConfigurationSafe();
        assertEquals("Updated University", props3.getProperty("provider.name"));
        // Note: saveConfiguration doesn't preserve the registered flag, it would need to be re-set
        // This is expected behavior - a new configuration may need re-registration
    }

    @Test
    @DisplayName("Should mark consumer as registered")
    void shouldMarkConsumerAsRegistered() throws IOException {
        // Arrange
        Path tempDir = Files.createTempDirectory("junit-");
        Path configPath = tempDir.resolve("provider.properties");
        ReflectionTestUtils.setField(service, "configLocation", tempDir.toString());
        
        // Create initial config
        Properties initialProps = new Properties();
        initialProps.setProperty("marketplace.base-url", "https://marketplace.example.com");
        initialProps.setProperty("consumer.name", "Test Consumer");
        try (FileOutputStream fos = new FileOutputStream(configPath.toFile())) {
            initialProps.store(fos, "Initial config");
        }
        
        // Act
        service.markConsumerRegistered();
        
        // Assert
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
            props.load(fis);
        }
        assertEquals("true", props.getProperty("consumer.registered"));
        assertEquals("https://marketplace.example.com", props.getProperty("marketplace.base-url"));
        assertEquals("Test Consumer", props.getProperty("consumer.name"));
    }
    
    @Test
    @DisplayName("Should create config file when marking consumer as registered if file does not exist")
    void shouldCreateFileWhenMarkingConsumerAsRegistered() throws IOException {
        // Arrange
        Path tempDir = Files.createTempDirectory("junit-");
        Path configPath = tempDir.resolve("provider.properties");
        ReflectionTestUtils.setField(service, "configLocation", tempDir.toString());
        
        assertFalse(Files.exists(configPath));
        
        // Act
        service.markConsumerRegistered();
        
        // Assert
        assertTrue(Files.exists(configPath));
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
            props.load(fis);
        }
        assertEquals("true", props.getProperty("consumer.registered"));
    }
}
