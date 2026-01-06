package decentralabs.blockchain.service.organization;

import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for InstitutionRegistrationService (Phase 4 consolidated)
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("InstitutionRegistrationService Tests")
class InstitutionRegistrationServiceTest {

    @Mock
    private InstitutionalWalletService walletService;

    @Mock
    private ProviderConfigurationPersistenceService configPersistenceService;

    @Mock
    private RestTemplate restTemplate;

    private InstitutionRegistrationService service;

    @BeforeEach
    void setUp() {
        service = new InstitutionRegistrationService(
                walletService,
                configPersistenceService,
                restTemplate
        );
    }

    @Test
    @DisplayName("Should register as provider successfully")
    void shouldRegisterAsProvider() throws IOException {
        // Arrange
        InstitutionRegistrationRequest request = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.PROVIDER)
                .marketplaceUrl("https://marketplace.example.com")
                .provisioningToken("token123")
                .organization("university.edu")
                .name("Test University")
                .email("test@university.edu")
                .country("US")
                .publicBaseUrl("https://gateway.university.edu")
                .build();

        when(walletService.getInstitutionalWalletAddress()).thenReturn("0xABC123");
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.status(HttpStatus.CREATED).body("Registration successful"));

        // Act
        boolean result = service.register(request);

        // Assert
        assertTrue(result);
        
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<HttpEntity<?>> entityCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).postForEntity(urlCaptor.capture(), entityCaptor.capture(), eq(String.class));
        
        assertTrue(urlCaptor.getValue().contains("/api/institutions/registerProvider"));
        verify(configPersistenceService).markAsRegistered(InstitutionRole.PROVIDER);
    }

    @Test
    @DisplayName("Should register as consumer successfully")
    void shouldRegisterAsConsumer() throws IOException {
        // Arrange
        InstitutionRegistrationRequest request = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.CONSUMER)
                .marketplaceUrl("https://marketplace.example.com")
                .provisioningToken("token456")
                .organization("consumer.edu")
                .build();

        when(walletService.getInstitutionalWalletAddress()).thenReturn("0xDEF456");
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.status(HttpStatus.CREATED).body("Registration successful"));

        // Act
        boolean result = service.register(request);

        // Assert
        assertTrue(result);
        
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(restTemplate).postForEntity(urlCaptor.capture(), any(HttpEntity.class), eq(String.class));
        
        assertTrue(urlCaptor.getValue().contains("/api/institutions/registerConsumer"));
        verify(configPersistenceService).markAsRegistered(InstitutionRole.CONSUMER);
    }


    @Test
    @DisplayName("Should throw exception when provider name is missing")
    void shouldThrowExceptionWhenProviderNameMissing() {
        // Arrange
        InstitutionRegistrationRequest request = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.PROVIDER)
                .marketplaceUrl("https://marketplace.example.com")
                .provisioningToken("token123")
                .organization("university.edu")
                .email("test@university.edu")
                .country("US")
                .publicBaseUrl("https://gateway.university.edu")
                .build();

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> service.register(request)
        );
        assertEquals("Provider name is required", exception.getMessage());
        verifyNoInteractions(restTemplate);
    }

    @Test
    @DisplayName("Should throw exception when marketplace URL is missing")
    void shouldThrowExceptionWhenMarketplaceUrlMissing() {
        // Arrange
        InstitutionRegistrationRequest request = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.CONSUMER)
                .provisioningToken("token456")
                .organization("consumer.edu")
                .build();

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> service.register(request)
        );
        assertEquals("Marketplace URL is required", exception.getMessage());
    }

    @Test
    @DisplayName("Should check provider registration status")
    void shouldCheckProviderRegistrationStatus() {
        // Arrange
        Properties props = new Properties();
        props.setProperty("provider.registered", "true");
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean result = service.isRegistered(InstitutionRole.PROVIDER);

        // Assert
        assertTrue(result);
    }

    @Test
    @DisplayName("Should check consumer registration status")
    void shouldCheckConsumerRegistrationStatus() {
        // Arrange
        Properties props = new Properties();
        props.setProperty("consumer.registered", "true");
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean result = service.isRegistered(InstitutionRole.CONSUMER);

        // Assert
        assertTrue(result);
    }

    @Test
    @DisplayName("Should mark provider as registered")
    void shouldMarkProviderAsRegistered() throws IOException {
        // Act
        service.markAsRegistered(InstitutionRole.PROVIDER);

        // Assert
        verify(configPersistenceService).markAsRegistered(InstitutionRole.PROVIDER);
        verify(configPersistenceService, never()).markAsRegistered(InstitutionRole.CONSUMER);
    }

    @Test
    @DisplayName("Should mark consumer as registered")
    void shouldMarkConsumerAsRegistered() throws IOException {
        // Act
        service.markAsRegistered(InstitutionRole.CONSUMER);

        // Assert
        verify(configPersistenceService).markAsRegistered(InstitutionRole.CONSUMER);
        verify(configPersistenceService, never()).markAsRegistered(InstitutionRole.PROVIDER);
    }

    @Test
    @DisplayName("Should get provider registration status from config")
    void shouldGetProviderRegistrationStatusFromConfig() {
        // Arrange
        Properties props = new Properties();
        props.setProperty("provider.registered", "true");
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean result = service.getRegistrationStatus(InstitutionRole.PROVIDER);

        // Assert
        assertTrue(result);
    }

    @Test
    @DisplayName("Should get consumer registration status from config")
    void shouldGetConsumerRegistrationStatusFromConfig() {
        // Arrange
        Properties props = new Properties();
        props.setProperty("consumer.registered", "true");
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean result = service.getRegistrationStatus(InstitutionRole.CONSUMER);

        // Assert
        assertTrue(result);
    }

    @Test
    @DisplayName("Should return false when registration status flag is missing")
    void shouldReturnFalseWhenRegistrationStatusFlagMissing() {
        // Arrange
        Properties props = new Properties();
        when(configPersistenceService.loadConfigurationSafe()).thenReturn(props);

        // Act
        boolean providerResult = service.getRegistrationStatus(InstitutionRole.PROVIDER);
        boolean consumerResult = service.getRegistrationStatus(InstitutionRole.CONSUMER);

        // Assert
        assertFalse(providerResult);
        assertFalse(consumerResult);
    }

    @Test
    @DisplayName("Should handle exception when checking registration status")
    void shouldHandleExceptionWhenCheckingRegistrationStatus() {
        // Arrange
        when(configPersistenceService.loadConfigurationSafe())
                .thenThrow(new RuntimeException("Config error"));

        // Act
        boolean result = service.getRegistrationStatus(InstitutionRole.PROVIDER);

        // Assert
        assertFalse(result);
    }


    @Test
    @DisplayName("Should handle already registered provider (CONFLICT status)")
    void shouldHandleAlreadyRegisteredProvider() throws IOException {
        // Arrange
        InstitutionRegistrationRequest request = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.PROVIDER)
                .marketplaceUrl("https://marketplace.example.com")
                .provisioningToken("token123")
                .organization("university.edu")
                .name("Test University")
                .email("test@university.edu")
                .country("US")
                .publicBaseUrl("https://gateway.university.edu")
                .build();

        when(walletService.getInstitutionalWalletAddress()).thenReturn("0xABC123");
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new HttpClientErrorException(HttpStatus.CONFLICT, "Already registered"));

        // Act
        boolean result = service.register(request);

        // Assert
        assertTrue(result); // CONFLICT is treated as success (already registered)
        verify(configPersistenceService).markAsRegistered(InstitutionRole.PROVIDER); // Marks as registered locally
    }

    @Test
    @DisplayName("Should handle unauthorized consumer registration")
    void shouldHandleUnauthorizedConsumerRegistration() throws IOException {
        // Arrange
        InstitutionRegistrationRequest request = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.CONSUMER)
                .marketplaceUrl("https://marketplace.example.com")
                .provisioningToken("token456")
                .organization("consumer.edu")
                .build();

        when(walletService.getInstitutionalWalletAddress()).thenReturn("0xDEF456");
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "Invalid token"));

        // Act
        boolean result = service.register(request);

        // Assert
        assertFalse(result); // UNAUTHORIZED causes registration failure
        verify(configPersistenceService, never()).markAsRegistered(InstitutionRole.CONSUMER);
    }

    @Test
    @DisplayName("Should handle HTTP client error during provider registration")
    void shouldHandleHttpClientErrorDuringProviderRegistration() {
        // Arrange
        InstitutionRegistrationRequest request = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.PROVIDER)
                .marketplaceUrl("https://marketplace.example.com")
                .provisioningToken("token123")
                .organization("university.edu")
                .name("Test University")
                .email("test@university.edu")
                .country("US")
                .publicBaseUrl("https://gateway.university.edu")
                .build();

        when(walletService.getInstitutionalWalletAddress()).thenReturn("0xABC123");
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new HttpClientErrorException(HttpStatus.INTERNAL_SERVER_ERROR, "Server error"));

        // Act
        boolean result = service.register(request);

        // Assert
        assertFalse(result);
    }

    @Test
    @DisplayName("Should normalize backend URL correctly")
    void shouldNormalizeBackendUrlCorrectly() throws IOException {
        // Arrange
        InstitutionRegistrationRequest request = InstitutionRegistrationRequest.builder()
                .role(InstitutionRole.PROVIDER)
                .marketplaceUrl("https://marketplace.example.com")
                .provisioningToken("token123")
                .organization("university.edu")
                .name("Test University")
                .email("test@university.edu")
                .country("US")
                .publicBaseUrl("  https://gateway.university.edu/  ")
                .build();

        when(walletService.getInstitutionalWalletAddress()).thenReturn("0xABC123");
        when(restTemplate.postForEntity(anyString(), any(HttpEntity.class), eq(String.class)))
                .thenReturn(ResponseEntity.status(HttpStatus.CREATED).body("Registration successful"));

        // Act
        boolean result = service.register(request);

        // Assert
        assertTrue(result);
        
        ArgumentCaptor<HttpEntity<?>> entityCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).postForEntity(anyString(), entityCaptor.capture(), eq(String.class));
        
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) entityCaptor.getValue().getBody();
        assertNotNull(body);
        
        // Verify authURI is normalized (no trailing slash, with trimmed whitespace)
        String authURI = (String) body.get("authURI");
        assertEquals("https://gateway.university.edu", authURI);
        
        // Verify backendUrl has /api appended
        String backendUrl = (String) body.get("backendUrl");
        assertEquals("https://gateway.university.edu/api", backendUrl);
    }
}
