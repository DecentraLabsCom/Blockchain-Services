package decentralabs.blockchain.controller.provider;

import decentralabs.blockchain.dto.provider.ProviderConfigurationRequest;
import decentralabs.blockchain.dto.provider.ProviderConfigurationResponse;
import decentralabs.blockchain.dto.provider.ProvisioningTokenRequest;
import decentralabs.blockchain.service.organization.InstitutionRegistrationService;
import decentralabs.blockchain.service.organization.ProviderConfigurationPersistenceService;
import decentralabs.blockchain.service.organization.ProvisioningTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ProviderConfigurationController Tests")
class ProviderConfigurationControllerTest {

    @Mock
    private InstitutionRegistrationService registrationService;

    @Mock
    private ProviderConfigurationPersistenceService persistenceService;

    @Mock
    private ProvisioningTokenService provisioningTokenService;

    @InjectMocks
    private ProviderConfigurationController controller;

    @BeforeEach
    void setUp() {
        // Set default values for @Value fields
        ReflectionTestUtils.setField(controller, "marketplaceBaseUrl", "https://marketplace.example.com");
        ReflectionTestUtils.setField(controller, "providerName", "");
        ReflectionTestUtils.setField(controller, "providerEmail", "");
        ReflectionTestUtils.setField(controller, "providerCountry", "");
        ReflectionTestUtils.setField(controller, "providerOrganization", "");
        ReflectionTestUtils.setField(controller, "publicBaseUrl", "");
    }

    @Test
    @DisplayName("Should return configuration status with registered=true when provider is registered")
    void shouldReturnRegisteredStatus() {
        // Prepare mock properties
        Properties props = new Properties();
        props.setProperty("marketplace.base-url", "https://marketplace.example.com");
        props.setProperty("provider.name", "UNED");
        props.setProperty("provider.email", "test@uned.es");
        props.setProperty("provider.country", "ES");
        props.setProperty("provider.organization", "uned.es");
        props.setProperty("public.base-url", "https://gateway.uned.es");
        props.setProperty("provisioning.source", "token");
        props.setProperty("provider.registered", "true");

        when(persistenceService.loadConfigurationSafe()).thenReturn(props);

        // Execute
        ResponseEntity<ProviderConfigurationResponse> response = controller.getConfigurationStatus();

        // Verify
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        ProviderConfigurationResponse body = response.getBody();
        assertTrue(body.isRegistered());
        assertTrue(body.isConfigured());
        assertTrue(body.isFromProvisioningToken());
        assertEquals("UNED", body.getProviderName());
        assertEquals("test@uned.es", body.getProviderEmail());
        assertEquals("ES", body.getProviderCountry());
        assertEquals("uned.es", body.getProviderOrganization());
        assertEquals("https://gateway.uned.es", body.getPublicBaseUrl());
    }

    @Test
    @DisplayName("Should return configuration status with registered=false when not registered")
    void shouldReturnNotRegisteredStatus() {
        // Prepare mock properties without registered flag
        Properties props = new Properties();
        props.setProperty("marketplace.base-url", "https://marketplace.example.com");
        props.setProperty("provider.name", "Test Uni");
        props.setProperty("provider.email", "test@test.edu");
        props.setProperty("provider.country", "US");
        props.setProperty("provider.organization", "test.edu");
        props.setProperty("public.base-url", "https://gateway.test.edu");
        props.setProperty("provisioning.source", "manual");

        when(persistenceService.loadConfigurationSafe()).thenReturn(props);

        // Execute
        ResponseEntity<ProviderConfigurationResponse> response = controller.getConfigurationStatus();

        // Verify
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        ProviderConfigurationResponse body = response.getBody();
        assertFalse(body.isRegistered());
        assertTrue(body.isConfigured());
        assertFalse(body.isFromProvisioningToken());
    }

    @Test
    @DisplayName("Should save configuration and mark as registered on successful registration")
    void shouldSaveAndMarkAsRegistered() throws Exception {
        // Prepare request
        ProviderConfigurationRequest request = new ProviderConfigurationRequest();
        request.setMarketplaceBaseUrl("https://marketplace.example.com");
        request.setProviderName("Test University");
        request.setProviderEmail("test@university.edu");
        request.setProviderCountry("US");
        request.setProviderOrganization("university.edu");
        request.setPublicBaseUrl("https://gateway.university.edu");
        request.setProvisioningToken("valid-token-123");

        // Mock successful registration
        when(registrationService.register(any())).thenReturn(true);

        // Execute
        ResponseEntity<Map<String, Object>> response = controller.saveAndRegister(request);

        // Verify
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(true, response.getBody().get("success"));
        assertEquals(true, response.getBody().get("registered"));

        // Verify persistence was called
        verify(persistenceService).saveConfiguration(request);
        verify(registrationService).markAsRegistered(any());
        verify(registrationService).register(any());
    }

    @Test
    @DisplayName("Should not mark as registered when registration fails")
    void shouldNotMarkAsRegisteredOnFailure() throws Exception {
        // Prepare request
        ProviderConfigurationRequest request = new ProviderConfigurationRequest();
        request.setMarketplaceBaseUrl("https://marketplace.example.com");
        request.setProviderName("Test University");
        request.setProviderEmail("test@university.edu");
        request.setProviderCountry("US");
        request.setProviderOrganization("university.edu");
        request.setPublicBaseUrl("https://gateway.university.edu");
        request.setProvisioningToken("valid-token-123");

        // Mock failed registration
        when(registrationService.register(any())).thenReturn(false);

        // Execute
        ResponseEntity<Map<String, Object>> response = controller.saveAndRegister(request);

        // Verify
        assertEquals(HttpStatus.PARTIAL_CONTENT, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(true, response.getBody().get("success"));
        assertEquals(false, response.getBody().get("registered"));

        // Verify persistence was called but NOT marked as registered
        verify(persistenceService).saveConfiguration(request);
        verify(registrationService, never()).markAsRegistered(any());
    }

    @Test
    @DisplayName("Should return error when provisioning token is missing")
    void shouldReturnErrorWhenTokenMissing() throws Exception {
        // Prepare request without token
        ProviderConfigurationRequest request = new ProviderConfigurationRequest();
        request.setMarketplaceBaseUrl("https://marketplace.example.com");
        request.setProviderName("Test University");
        request.setProviderEmail("test@university.edu");
        request.setProviderCountry("US");
        request.setProviderOrganization("university.edu");
        request.setPublicBaseUrl("https://gateway.university.edu");
        request.setProvisioningToken("");

        // Execute
        ResponseEntity<Map<String, Object>> response = controller.saveAndRegister(request);

        // Verify
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(false, response.getBody().get("success"));
        assertTrue(response.getBody().get("error").toString().contains("Provisioning token is required"));

        // Verify no persistence or registration was attempted
        verify(persistenceService, never()).saveConfiguration(any());
        verify(registrationService, never()).markAsRegistered(any());
        verify(registrationService, never()).register(any());
    }

    @Test
    @DisplayName("Should mark as registered after successful token application")
    void shouldMarkAsRegisteredAfterTokenApplication() throws Exception {
        // Prepare token request
        ProvisioningTokenRequest tokenRequest = new ProvisioningTokenRequest();
        tokenRequest.setToken("valid-jwt-token");

        // Mock token validation and extraction
        var payload = decentralabs.blockchain.dto.provider.ProvisioningTokenPayload.builder()
            .marketplaceBaseUrl("https://marketplace.example.com")
            .providerName("Token University")
            .providerEmail("token@university.edu")
            .providerCountry("ES")
            .providerOrganization("token.edu")
            .publicBaseUrl("https://token.university.edu")
            .jti("test-jti-123")
            .build();

        Properties emptyProps = new Properties();
        when(persistenceService.loadConfigurationSafe()).thenReturn(emptyProps);
        when(provisioningTokenService.validateAndExtract(anyString(), anyString(), anyString()))
            .thenReturn(payload);
        when(registrationService.register(any())).thenReturn(true);

        // Execute
        ResponseEntity<Map<String, Object>> response = controller.applyProvisioningToken(tokenRequest);

        // Verify
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(true, response.getBody().get("success"));
        assertEquals(true, response.getBody().get("registered"));

        // Verify marked as registered
        verify(persistenceService).saveConfigurationFromToken(payload);
        verify(registrationService).markAsRegistered(any());
    }

    @Test
    @DisplayName("Should handle empty configuration properties correctly")
    void shouldHandleEmptyConfiguration() {
        // Empty properties
        Properties props = new Properties();
        when(persistenceService.loadConfigurationSafe()).thenReturn(props);

        // Execute
        ResponseEntity<ProviderConfigurationResponse> response = controller.getConfigurationStatus();

        // Verify
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        ProviderConfigurationResponse body = response.getBody();
        assertFalse(body.isRegistered());
        assertFalse(body.isConfigured());
    }
}
