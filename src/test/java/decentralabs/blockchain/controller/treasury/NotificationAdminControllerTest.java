package decentralabs.blockchain.controller.treasury;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import decentralabs.blockchain.notification.MailDriver;
import decentralabs.blockchain.notification.MailSenderAdapter;
import decentralabs.blockchain.notification.MailSenderFactory;
import decentralabs.blockchain.notification.NotificationConfigService;
import decentralabs.blockchain.notification.NotificationProperties;
import decentralabs.blockchain.notification.NotificationUpdateRequest;

/**
 * Unit tests for NotificationAdminController.
 * Tests notification configuration and testing endpoints.
 */
@ExtendWith(MockitoExtension.class)
class NotificationAdminControllerTest {

    @Mock
    private NotificationConfigService notificationConfigService;

    @Mock
    private MailSenderFactory mailSenderFactory;

    @InjectMocks
    private NotificationAdminController notificationAdminController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        // Disable localhost-only check for testing
        ReflectionTestUtils.setField(notificationAdminController, "adminDashboardLocalOnly", false);
        ReflectionTestUtils.setField(notificationAdminController, "adminDashboardAllowPrivate", true);
        mockMvc = MockMvcBuilders.standaloneSetup(notificationAdminController).build();
        objectMapper = new ObjectMapper();
    }

    @Nested
    @DisplayName("Get Config Endpoint Tests")
    class GetConfigTests {

        @Test
        @DisplayName("Should get notification config successfully")
        void shouldGetConfigSuccessfully() throws Exception {
            Map<String, Object> publicConfig = Map.of(
                "enabled", true,
                "driver", "smtp",
                "from", "noreply@example.com"
            );

            when(notificationConfigService.getPublicConfig()).thenReturn(publicConfig);

            mockMvc.perform(get("/treasury/admin/notifications"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.config.enabled").value(true));
        }
    }

    @Nested
    @DisplayName("Update Config Endpoint Tests")
    class UpdateConfigTests {

        @Test
        @DisplayName("Should update notification config successfully")
        void shouldUpdateConfigSuccessfully() throws Exception {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true,
                MailDriver.SMTP,
                "noreply@example.com",
                "Lab Gateway",
                List.of("admin@example.com"),
                "UTC",
                new NotificationUpdateRequest.Smtp(
                    "smtp.example.com",
                    587,
                    "user",
                    "pass",
                    true,
                    true,
                    5000
                ),
                null
            );

            NotificationProperties.Mail mailConfig = new NotificationProperties.Mail();
            mailConfig.setEnabled(true);

            when(notificationConfigService.validateUpdate(any())).thenReturn(Collections.emptyList());
            when(notificationConfigService.updateMailConfig(any())).thenReturn(mailConfig);

            mockMvc.perform(post("/treasury/admin/notifications")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should reject invalid config update")
        void shouldRejectInvalidConfigUpdate() throws Exception {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true,
                MailDriver.SMTP,
                null, // Missing from address
                null,
                Collections.emptyList(),
                null,
                null,
                null
            );

            when(notificationConfigService.validateUpdate(any()))
                .thenReturn(List.of("From address is required", "SMTP configuration is required"));

            mockMvc.perform(post("/treasury/admin/notifications")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").exists());
        }

        @Test
        @DisplayName("Should handle error during config update")
        void shouldHandleErrorDuringUpdate() throws Exception {
            NotificationUpdateRequest request = new NotificationUpdateRequest(
                true, MailDriver.SMTP, "from@example.com", "Test",
                List.of("to@example.com"), "UTC", null, null
            );

            when(notificationConfigService.validateUpdate(any())).thenReturn(Collections.emptyList());
            when(notificationConfigService.updateMailConfig(any()))
                .thenThrow(new RuntimeException("Database error"));

            mockMvc.perform(post("/treasury/admin/notifications")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success").value(false));
        }
    }

    @Nested
    @DisplayName("Test Notification Endpoint Tests")
    class TestNotificationTests {

        @Test
        @DisplayName("Should send test notification successfully")
        void shouldSendTestSuccessfully() throws Exception {
            NotificationProperties.Mail mailConfig = new NotificationProperties.Mail();
            mailConfig.setDefaultTo(List.of("admin@example.com"));

            when(notificationConfigService.getMailConfig()).thenReturn(mailConfig);
            when(notificationConfigService.validateMailConfig()).thenReturn(Collections.emptyList());
            
            MailSenderAdapter mockSender = org.mockito.Mockito.mock(MailSenderAdapter.class);
            when(mailSenderFactory.resolve()).thenReturn(mockSender);

            mockMvc.perform(post("/treasury/admin/notifications/test"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should reject test when mail config invalid")
        void shouldRejectTestWhenConfigInvalid() throws Exception {
            NotificationProperties.Mail mailConfig = new NotificationProperties.Mail();

            when(notificationConfigService.getMailConfig()).thenReturn(mailConfig);
            when(notificationConfigService.validateMailConfig())
                .thenReturn(List.of("SMTP host is required"));

            mockMvc.perform(post("/treasury/admin/notifications/test"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").exists());
        }

        @Test
        @DisplayName("Should reject test when no recipients configured")
        void shouldRejectTestWhenNoRecipients() throws Exception {
            NotificationProperties.Mail mailConfig = new NotificationProperties.Mail();
            mailConfig.setDefaultTo(Collections.emptyList());

            when(notificationConfigService.getMailConfig()).thenReturn(mailConfig);
            when(notificationConfigService.validateMailConfig()).thenReturn(Collections.emptyList());

            mockMvc.perform(post("/treasury/admin/notifications/test"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").value("No recipients configured (defaultTo is empty)"));
        }

        @Test
        @DisplayName("Should handle error during send")
        void shouldHandleErrorDuringSend() throws Exception {
            NotificationProperties.Mail mailConfig = new NotificationProperties.Mail();
            mailConfig.setDefaultTo(List.of("admin@example.com"));

            when(notificationConfigService.getMailConfig()).thenReturn(mailConfig);
            when(notificationConfigService.validateMailConfig()).thenReturn(Collections.emptyList());
            when(mailSenderFactory.resolve()).thenThrow(new RuntimeException("SMTP connection failed"));

            mockMvc.perform(post("/treasury/admin/notifications/test"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success").value(false));
        }
    }

    @Nested
    @DisplayName("Access Control Tests")
    class AccessControlTests {

        @BeforeEach
        void setUpAccess() {
            ReflectionTestUtils.setField(notificationAdminController, "adminDashboardLocalOnly", true);
            ReflectionTestUtils.setField(notificationAdminController, "adminDashboardAllowPrivate", true);
            ReflectionTestUtils.setField(notificationAdminController, "allowPrivateNetworks", true);
            ReflectionTestUtils.setField(notificationAdminController, "accessToken", "test-token");
            ReflectionTestUtils.setField(notificationAdminController, "accessTokenHeader", "X-Access-Token");
            ReflectionTestUtils.setField(notificationAdminController, "accessTokenCookie", "access_token");
            ReflectionTestUtils.setField(notificationAdminController, "accessTokenRequired", true);
            mockMvc = MockMvcBuilders.standaloneSetup(notificationAdminController).build();
        }

        @Test
        @DisplayName("Should reject private network without access token")
        void shouldRejectPrivateNetworkWithoutToken() throws Exception {
            mockMvc.perform(get("/treasury/admin/notifications")
                    .with(req -> { req.setRemoteAddr("10.0.0.5"); return req; }))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success").value(false));
        }

        @Test
        @DisplayName("Should allow private network with valid access token")
        void shouldAllowPrivateNetworkWithToken() throws Exception {
            when(notificationConfigService.getPublicConfig()).thenReturn(Map.of("enabled", false));

            mockMvc.perform(get("/treasury/admin/notifications")
                    .header("X-Access-Token", "test-token")
                    .with(req -> { req.setRemoteAddr("10.0.0.5"); return req; }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }
    }
}
