package decentralabs.blockchain.controller.provider;

import decentralabs.blockchain.dto.provider.ProviderConfigurationRequest;
import decentralabs.blockchain.dto.provider.ProviderConfigurationResponse;
import decentralabs.blockchain.dto.provider.ProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProvisioningTokenRequest;
import decentralabs.blockchain.service.organization.InstitutionRegistrationRequest;
import decentralabs.blockchain.service.organization.InstitutionRegistrationService;
import decentralabs.blockchain.service.organization.InstitutionOnChainStatusService;
import decentralabs.blockchain.service.organization.ProviderConfigurationPersistenceService;
import decentralabs.blockchain.service.organization.ProvisioningTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.ArgumentCaptor;
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

    @Mock
    private InstitutionOnChainStatusService onChainStatusService;

    @InjectMocks
    private ProviderConfigurationController controller;

    @BeforeEach
    void setUp() {
        // Set default values for @Value fields
        ReflectionTestUtils.setField(controller, "marketplaceBaseUrl", "https://marketplace.example.com");
        ReflectionTestUtils.setField(controller, "providersEnabled", true);
        ReflectionTestUtils.setField(controller, "providerRegistrationEnabled", true);
        ReflectionTestUtils.setField(controller, "providerName", "");
        ReflectionTestUtils.setField(controller, "providerEmail", "");
        ReflectionTestUtils.setField(controller, "providerCountry", "");
        ReflectionTestUtils.setField(controller, "providerOrganization", "");
        ReflectionTestUtils.setField(controller, "publicBaseUrl", "");
        lenient().when(onChainStatusService.inspect(anyString(), anyString(), anyBoolean()))
            .thenReturn(InstitutionOnChainStatusService.Status.unavailable());
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
        when(onChainStatusService.inspect("uned.es", "https://gateway.uned.es", true))
            .thenReturn(new InstitutionOnChainStatusService.Status(
                true,
                "0x00000000000000000000000000000000000000aa",
                true,
                true,
                "0x00000000000000000000000000000000000000aa",
                "https://gateway.uned.es",
                "0x00000000000000000000000000000000000000aa",
                "ACTIVE",
                true
            ));

        // Execute
        ResponseEntity<ProviderConfigurationResponse> response = controller.getConfigurationStatus();

        // Verify
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        
        ProviderConfigurationResponse body = response.getBody();
        assertTrue(body.isRegistered());
        assertTrue(body.isConfigured());
        assertTrue(body.isFromProvisioningToken());
        assertTrue(body.isProviderRegistered());
        assertFalse(body.isConsumerRegistered());
        assertEquals("provider-consumer", body.getOperatingMode());
        assertEquals("PROVIDER", body.getRegistrationRole());
        assertEquals("UNED", body.getProviderName());
        assertEquals("test@uned.es", body.getProviderEmail());
        assertEquals("ES", body.getProviderCountry());
        assertEquals("uned.es", body.getProviderOrganization());
        assertTrue(body.isLocalConfigSaved());
        assertTrue(body.isLocalRegistrationCached());
        assertTrue(body.isOnChainStatusAvailable());
        assertTrue(body.isProviderRoleOnChain());
        assertTrue(body.isInstitutionRoleOnChain());
        assertEquals("ACTIVE", body.getProviderNetworkStatus());
        assertTrue(body.isFullyOperational());
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
        assertTrue(body.isProviderRegistrationEnabled());
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

        ProvisioningTokenPayload payload = providerPayload();
        when(provisioningTokenService.validateAndExtract(
            "valid-token-123",
            "https://marketplace.example.com",
            "https://gateway.university.edu"
        )).thenReturn(payload);
        when(registrationService.register(any())).thenReturn(true);

        // Execute
        ResponseEntity<Map<String, Object>> response = controller.saveAndRegister(request);

        // Verify
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(true, response.getBody().get("success"));
        assertEquals(true, response.getBody().get("registered"));

        verify(persistenceService).saveConfigurationFromToken(payload);
        verify(persistenceService, never()).saveConfiguration(any());
        verify(registrationService).markAsRegistered(any());
        ArgumentCaptor<InstitutionRegistrationRequest> captor =
            ArgumentCaptor.forClass(InstitutionRegistrationRequest.class);
        verify(registrationService).register(captor.capture());
        assertEquals(payload.getWalletAddress(), captor.getValue().getWalletAddress());
        assertEquals(payload.getJti(), captor.getValue().getProvisioningJti());
        assertEquals(payload.getRegistrationNonce(), captor.getValue().getRegistrationNonce());
        assertEquals(payload.getChainId(), captor.getValue().getChainId());
        assertEquals(payload.getVerifyingContract(), captor.getValue().getVerifyingContract());
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

        ProvisioningTokenPayload payload = providerPayload();
        when(provisioningTokenService.validateAndExtract(anyString(), anyString(), anyString()))
            .thenReturn(payload);
        when(registrationService.register(any())).thenReturn(false);

        // Execute
        ResponseEntity<Map<String, Object>> response = controller.saveAndRegister(request);

        // Verify
        assertEquals(HttpStatus.PARTIAL_CONTENT, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(true, response.getBody().get("success"));
        assertEquals(false, response.getBody().get("registered"));

        // Failed registrations must not persist unverified or partial configuration.
        verify(persistenceService, never()).saveConfiguration(any());
        verify(persistenceService, never()).saveConfigurationFromToken(any());
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
    @DisplayName("Should return partial content when token is valid but registration does not complete")
    void shouldReturnPartialContentWhenTokenApplicationRegistrationFails() throws Exception {
        ProvisioningTokenRequest tokenRequest = new ProvisioningTokenRequest();
        tokenRequest.setToken("valid-jwt-token");

        var payload = decentralabs.blockchain.dto.provider.ProvisioningTokenPayload.builder()
            .marketplaceBaseUrl("https://marketplace.example.com")
            .providerName("Token University")
            .providerEmail("token@university.edu")
            .providerCountry("ES")
            .providerOrganization("token.edu")
            .publicBaseUrl("https://token.university.edu")
            .jti("test-jti-124")
            .build();

        Properties emptyProps = new Properties();
        when(persistenceService.loadConfigurationSafe()).thenReturn(emptyProps);
        when(provisioningTokenService.validateAndExtract(anyString(), anyString(), anyString()))
            .thenReturn(payload);
        when(registrationService.register(any())).thenReturn(false);

        ResponseEntity<Map<String, Object>> response = controller.applyProvisioningToken(tokenRequest);

        assertEquals(HttpStatus.PARTIAL_CONTENT, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(true, response.getBody().get("success"));
        assertEquals(false, response.getBody().get("registered"));

        verify(persistenceService, never()).saveConfigurationFromToken(payload);
        verify(registrationService, never()).markAsRegistered(any());
    }

    @Test
    @DisplayName("Should return clear error when provisioning token is expired")
    void shouldReturnClearErrorWhenProvisioningTokenExpired() throws Exception {
        ProvisioningTokenRequest tokenRequest = new ProvisioningTokenRequest();
        tokenRequest.setToken("expired-jwt-token");

        Properties emptyProps = new Properties();
        when(persistenceService.loadConfigurationSafe()).thenReturn(emptyProps);
        when(provisioningTokenService.validateAndExtract(anyString(), anyString(), anyString()))
            .thenThrow(new IllegalArgumentException("Provisioning token expired"));

        ResponseEntity<Map<String, Object>> response = controller.applyProvisioningToken(tokenRequest);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(false, response.getBody().get("success"));
        assertEquals("Provisioning token expired", response.getBody().get("error"));

        verify(persistenceService, never()).saveConfigurationFromToken(any());
        verify(registrationService, never()).register(any());
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

    @Test
    @DisplayName("Should report consumer registration as registered in consumer-only mode")
    void shouldReturnConsumerRegisteredStatus() {
        ReflectionTestUtils.setField(controller, "providersEnabled", false);
        ReflectionTestUtils.setField(controller, "providerRegistrationEnabled", false);

        Properties props = new Properties();
        props.setProperty("marketplace.base-url", "https://marketplace.example.com");
        props.setProperty("consumer.name", "Consumer University");
        props.setProperty("provider.organization", "consumer.edu");
        props.setProperty("provisioning.source", "consumer-token");
        props.setProperty("consumer.registered", "true");

        when(persistenceService.loadConfigurationSafe()).thenReturn(props);

        ResponseEntity<ProviderConfigurationResponse> response = controller.getConfigurationStatus();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        ProviderConfigurationResponse body = response.getBody();
        assertTrue(body.isRegistered());
        assertTrue(body.isConsumerRegistered());
        assertFalse(body.isProviderRegistered());
        assertTrue(body.isConfigured());
        assertEquals("consumer-only", body.getOperatingMode());
        assertEquals("CONSUMER", body.getRegistrationRole());
        assertFalse(body.isProviderRegistrationEnabled());
        assertEquals("Consumer University", body.getConsumerName());
    }

    @Test
    @DisplayName("Should reject provider registration when provider mode is disabled")
    void shouldRejectProviderRegistrationWhenDisabled() throws Exception {
        ReflectionTestUtils.setField(controller, "providerRegistrationEnabled", false);

        ProviderConfigurationRequest request = new ProviderConfigurationRequest();
        request.setMarketplaceBaseUrl("https://marketplace.example.com");
        request.setProviderName("Test University");
        request.setProviderEmail("test@university.edu");
        request.setProviderCountry("US");
        request.setProviderOrganization("university.edu");
        request.setPublicBaseUrl("https://gateway.university.edu");
        request.setProvisioningToken("valid-token-123");

        ResponseEntity<Map<String, Object>> response = controller.saveAndRegister(request);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(false, response.getBody().get("success"));
        assertTrue(response.getBody().get("error").toString().contains("Provider registration is disabled"));

        verify(persistenceService, never()).saveConfiguration(any());
        verify(registrationService, never()).register(any());
    }

    @Test
    @DisplayName("Should retry provider registration using only validated token claims")
    void shouldRetryUsingValidatedTokenClaims() throws Exception {
        Properties props = new Properties();
        props.setProperty("marketplace.base-url", "https://marketplace.example.com");
        props.setProperty("provider.name", "Stale Name");
        props.setProperty("provider.email", "stale@example.com");
        props.setProperty("provider.country", "ES");
        props.setProperty("provider.organization", "stale.example");
        props.setProperty("public.base-url", "https://gateway.university.edu");
        when(persistenceService.loadConfigurationSafe()).thenReturn(props);

        ProvisioningTokenPayload payload = providerPayload();
        when(provisioningTokenService.validateAndExtract(
            "valid-token-123",
            "https://marketplace.example.com",
            "https://gateway.university.edu"
        )).thenReturn(payload);
        when(registrationService.register(any())).thenReturn(true);

        ResponseEntity<Map<String, Object>> response = controller.retryRegistration(
            Map.of("provisioningToken", "valid-token-123")
        );

        assertEquals(HttpStatus.OK, response.getStatusCode());
        ArgumentCaptor<InstitutionRegistrationRequest> captor =
            ArgumentCaptor.forClass(InstitutionRegistrationRequest.class);
        verify(registrationService).register(captor.capture());
        assertEquals(payload.getProviderOrganization(), captor.getValue().getOrganization());
        assertEquals(payload.getWalletAddress(), captor.getValue().getWalletAddress());
        verify(persistenceService).saveConfigurationFromToken(payload);
    }

    private ProvisioningTokenPayload providerPayload() {
        return ProvisioningTokenPayload.builder()
            .marketplaceBaseUrl("https://marketplace.example.com")
            .providerName("Test University")
            .providerEmail("test@university.edu")
            .providerCountry("US")
            .providerOrganization("university.edu")
            .publicBaseUrl("https://gateway.university.edu")
            .walletAddress("0x1111111111111111111111111111111111111111")
            .jti("test-jti-123")
            .registrationNonce("registration-nonce-123")
            .chainId(11155111L)
            .verifyingContract("0xe49a2f59631717691642f929E0FeF1f705866600")
            .build();
    }
}
