package decentralabs.blockchain.controller.billing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.security.AdminNetworkAccessPolicy;
import jakarta.servlet.http.Cookie;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class ContractEventAdminControllerTest {

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private AdminNetworkAccessPolicy adminNetworkAccessPolicy;

    private ContractEventAdminController controller;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        controller = new ContractEventAdminController(jdbcTemplateProvider, adminNetworkAccessPolicy);
        ReflectionTestUtils.setField(controller, "accessToken", "admin-secret");
        ReflectionTestUtils.setField(controller, "accessTokenHeader", "X-Access-Token");
        ReflectionTestUtils.setField(controller, "accessTokenCookie", "access_token");
        ReflectionTestUtils.setField(controller, "accessTokenRequired", true);
        when(adminNetworkAccessPolicy.isRequestAllowed(any(), any())).thenAnswer(invocation ->
            ((BooleanSupplier) invocation.getArgument(1)).getAsBoolean()
        );
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void rejectsRequestsWithoutAValidAdministrativeToken() throws Exception {
        mockMvc.perform(get("/billing/admin/contract-events/dead-letter"))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("Access denied"));

        verify(jdbcTemplateProvider, never()).getIfAvailable();
    }

    @Test
    void rejectsRequestsWhenAdministrativeTokenIsNotConfigured() throws Exception {
        ReflectionTestUtils.setField(controller, "accessToken", " ");

        mockMvc.perform(get("/billing/admin/contract-events/dead-letter")
                .header("X-Access-Token", "admin-secret"))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.error").value("Access denied"));

        verify(jdbcTemplateProvider, never()).getIfAvailable();
    }

    @Test
    void returnsServiceUnavailableWhenJdbcIsNotConfigured() throws Exception {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(null);

        mockMvc.perform(get("/billing/admin/contract-events/dead-letter")
                .header("X-Access-Token", "admin-secret"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error").value("Database unavailable"));
    }

    @Test
    void returnsDeadLettersAndBoundsTheRequestedLimit() throws Exception {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.queryForList(anyString())).thenReturn(List.of(
            Map.of("event_name", "ReservationRequested", "status", "DEAD_LETTER")
        ));

        mockMvc.perform(get("/billing/admin/contract-events/dead-letter")
                .header("X-Access-Token", "admin-secret")
                .param("limit", "600"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.count").value(1))
            .andExpect(jsonPath("$.events[0].event_name").value("ReservationRequested"));

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate).queryForList(sql.capture());
        assertThat(sql.getValue()).endsWith("LIMIT 500");
    }

    @Test
    void clampsNonPositiveLimitToOne() throws Exception {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.queryForList(anyString())).thenReturn(List.of());

        mockMvc.perform(get("/billing/admin/contract-events/dead-letter")
                .header("X-Access-Token", " admin-secret ")
                .param("limit", "0"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.count").value(0))
            .andExpect(jsonPath("$.events").isArray());

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate).queryForList(sql.capture());
        assertThat(sql.getValue()).endsWith("LIMIT 1");
    }

    @Test
    void acceptsCookieTokenAndCanDisableTokenRequirement() throws Exception {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.queryForList(anyString())).thenReturn(List.of());

        mockMvc.perform(get("/billing/admin/contract-events/dead-letter")
                .cookie(new Cookie("access_token", "admin-secret")))
            .andExpect(status().isOk());

        ReflectionTestUtils.setField(controller, "accessTokenRequired", false);
        mockMvc.perform(get("/billing/admin/contract-events/dead-letter"))
            .andExpect(status().isOk());
    }

    @Test
    void rejectsWrongHeaderTokenEvenWhenDatabaseIsAvailable() throws Exception {
        mockMvc.perform(get("/billing/admin/contract-events/dead-letter")
                .header("X-Access-Token", "wrong-token"))
            .andExpect(status().isForbidden());

        verify(jdbcTemplate, never()).queryForList(anyString());
    }
}
