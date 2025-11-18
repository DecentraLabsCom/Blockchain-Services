package decentralabs.blockchain.controller.organization;

import decentralabs.blockchain.dto.organization.InstitutionInviteTokenResponse;
import decentralabs.blockchain.service.organization.InstitutionInviteService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = InstitutionInviteController.class)
@AutoConfigureMockMvc(addFilters = false)
class InstitutionInviteControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private InstitutionInviteService inviteService;

    @Test
    void applyInviteReturnsServicePayload() throws Exception {
        InstitutionInviteTokenResponse response = InstitutionInviteTokenResponse.builder()
            .success(true)
            .walletAddress("0xabc")
            .message("ok")
            .build();
        when(inviteService.applyInvite(org.mockito.ArgumentMatchers.any())).thenReturn(response);

        mockMvc.perform(post("/onboarding/token/apply")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "token": "signed-token",
                      "walletAddress": "0xabc"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.walletAddress").value("0xabc"))
            .andExpect(jsonPath("$.message").value("ok"));

        ArgumentCaptor<decentralabs.blockchain.dto.organization.InstitutionInviteTokenRequest> captor =
            ArgumentCaptor.forClass(decentralabs.blockchain.dto.organization.InstitutionInviteTokenRequest.class);
        verify(inviteService).applyInvite(captor.capture());
        assertThat(captor.getValue().getToken()).isEqualTo("signed-token");
        assertThat(captor.getValue().getWalletAddress()).isEqualTo("0xabc");
    }

    @Test
    void applyInviteValidatesBlankToken() throws Exception {
        mockMvc.perform(post("/onboarding/token/apply")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "token": "",
                      "walletAddress": "0xabc"
                    }
                    """))
            .andExpect(status().isBadRequest());

        verifyNoInteractions(inviteService);
    }
}
