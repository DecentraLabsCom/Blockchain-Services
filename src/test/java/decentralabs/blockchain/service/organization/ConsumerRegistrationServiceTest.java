package decentralabs.blockchain.service.organization;

import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for ConsumerRegistrationService
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ConsumerRegistrationService Tests")
class ConsumerRegistrationServiceTest {

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private ProviderConfigurationPersistenceService configPersistenceService;

    @InjectMocks
    private ConsumerRegistrationService service;

    @BeforeEach
    void setUp() {
        // Set public base URL for tests
        ReflectionTestUtils.setField(service, "publicBaseUrl", "https://consumer.example.com");
    }

    @Test
    @DisplayName("Should return true when consumer.registered=true in config")
    void shouldReturnTrueWhenConsumerRegisteredInConfig() {
        // Arrange
        Properties props = new Properties();
        props.setProperty("consumer.registered", "true");
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean result = service.isConsumerRegistered();

        // Assert
        assertTrue(result);
        verify(configPersistenceService).loadConfigurationSafe();
    }

    @Test
    @DisplayName("Should return false when consumer.registered=false in config")
    void shouldReturnFalseWhenConsumerNotRegisteredInConfig() {
        // Arrange
        Properties props = new Properties();
        props.setProperty("consumer.registered", "false");
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean result = service.isConsumerRegistered();

        // Assert
        assertFalse(result);
    }

    @Test
    @DisplayName("Should return false when consumer.registered property missing")
    void shouldReturnFalseWhenRegisteredPropertyMissing() {
        // Arrange
        Properties props = new Properties();
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean result = service.isConsumerRegistered();

        // Assert
        assertFalse(result);
    }

    @Test
    @DisplayName("Should handle case-insensitive true values for consumer.registered")
    void shouldHandleCaseInsensitiveTrueValues() {
        // Arrange
        Properties props = new Properties();
        props.setProperty("consumer.registered", "TRUE");
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean result = service.isConsumerRegistered();

        // Assert
        assertTrue(result);
    }

    @Test
    @DisplayName("Should return false when loadConfigurationSafe throws exception")
    void shouldReturnFalseOnException() {
        // Arrange
        when(configPersistenceService.loadConfigurationSafe())
            .thenThrow(new RuntimeException("Config file not found"));

        // Act
        boolean result = service.isConsumerRegistered();

        // Assert
        assertFalse(result);
    }

    @Test
    @DisplayName("Should return false when wallet address not available")
    void shouldReturnFalseWhenWalletNotAvailable() {
        // Arrange
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(null);

        // Act
        boolean result = service.registerConsumer(
            "https://marketplace.example.com",
            "example.edu",
            "valid-token"
        );

        // Assert
        assertFalse(result);
        verify(institutionalWalletService).getInstitutionalWalletAddress();
    }

    @Test
    @DisplayName("Should return false when provisioning token is blank")
    void shouldReturnFalseWhenTokenIsBlank() {
        // Arrange
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x1234567890abcdef");

        // Act
        boolean result = service.registerConsumer(
            "https://marketplace.example.com",
            "example.edu",
            ""
        );

        // Assert
        assertFalse(result);
    }

    @Test
    @DisplayName("Should return false when provisioning token is null")
    void shouldReturnFalseWhenTokenIsNull() {
        // Arrange
        when(institutionalWalletService.getInstitutionalWalletAddress())
            .thenReturn("0x1234567890abcdef");

        // Act
        boolean result = service.registerConsumer(
            "https://marketplace.example.com",
            "example.edu",
            null
        );

        // Assert
        assertFalse(result);
    }
}
