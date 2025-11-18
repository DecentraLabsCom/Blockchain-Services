package decentralabs.blockchain.service.organization;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.organization.InstitutionInviteTokenRequest;
import decentralabs.blockchain.dto.organization.InstitutionInviteTokenResponse;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class InstitutionInviteServiceTest {

    private static final String LOCAL_WALLET = "0xDeAdBeeF";
    private static final String HMAC_SECRET = "test-secret";

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private Diamond diamond;

    @Mock
    private RemoteFunctionCall<TransactionReceipt> remoteFunctionCall;

    @Mock
    private RemoteFunctionCall<TransactionReceipt> remoteFunctionCallFailure;

    private InstitutionInviteService inviteService;

    @BeforeEach
    void setUp() {
        inviteService = new InstitutionInviteService(walletService, institutionalWalletService);
        ReflectionTestUtils.setField(inviteService, "diamondContractAddress", "0xdiamond");
        ReflectionTestUtils.setField(inviteService, "contractGasLimit", 125_000L);
        ReflectionTestUtils.setField(inviteService, "defaultGasPriceGwei", 2.0d);
        ReflectionTestUtils.setField(inviteService, "inviteSecret", HMAC_SECRET);
        ReflectionTestUtils.setField(inviteService, "defaultIssuer", "marketplace");
        ReflectionTestUtils.setField(inviteService, "cachedDiamond", diamond);

        lenient().when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(LOCAL_WALLET);
    }

    @Test
    void applyInviteGrantsInstitutionRolePerDomain() throws Exception {
        List<String> organizations = List.of("Example.edu ", "Second.Org");
        String token = buildToken(organizations, null);
        InstitutionInviteTokenRequest request = new InstitutionInviteTokenRequest();
        request.setToken(token);

        TransactionReceipt firstReceipt = new TransactionReceipt();
        firstReceipt.setTransactionHash("0xaaa");
        TransactionReceipt secondReceipt = new TransactionReceipt();
        secondReceipt.setTransactionHash("0xbbb");

        when(diamond.grantInstitutionRole(anyString(), anyString())).thenReturn(remoteFunctionCall);
        when(remoteFunctionCall.send()).thenReturn(firstReceipt, secondReceipt);

        InstitutionInviteTokenResponse response = inviteService.applyInvite(request);

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getWalletAddress()).isEqualTo(LOCAL_WALLET.toLowerCase(Locale.ROOT));
        assertThat(response.getDomains())
            .extracting(InstitutionInviteTokenResponse.DomainResult::getOrganization)
            .containsExactly("example.edu", "second.org");
        assertThat(response.getDomains())
            .extracting(InstitutionInviteTokenResponse.DomainResult::getTransactionHash)
            .containsExactly("0xaaa", "0xbbb");

        ArgumentCaptor<String> orgCaptor = ArgumentCaptor.forClass(String.class);
        verify(diamond, times(2)).grantInstitutionRole(eq(LOCAL_WALLET.toLowerCase(Locale.ROOT)), orgCaptor.capture());
        assertThat(orgCaptor.getAllValues()).containsExactly("example.edu", "second.org");
    }

    @Test
    void applyInviteCapturesPartialFailures() throws Exception {
        List<String> organizations = List.of("Example.edu", "Another.edu");
        String token = buildToken(organizations, null);
        InstitutionInviteTokenRequest request = new InstitutionInviteTokenRequest();
        request.setToken(token);

        TransactionReceipt receipt = new TransactionReceipt();
        receipt.setTransactionHash("0xabc");

        when(diamond.grantInstitutionRole(eq(LOCAL_WALLET.toLowerCase(Locale.ROOT)), eq("example.edu")))
            .thenReturn(remoteFunctionCall);
        when(remoteFunctionCall.send()).thenReturn(receipt);

        when(diamond.grantInstitutionRole(eq(LOCAL_WALLET.toLowerCase(Locale.ROOT)), eq("another.edu")))
            .thenReturn(remoteFunctionCallFailure);
        when(remoteFunctionCallFailure.send()).thenThrow(new IllegalStateException("Contract reverted"));

        InstitutionInviteTokenResponse response = inviteService.applyInvite(request);

        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getMessage()).contains("Some organizations could not be registered");
        assertThat(response.getDomains())
            .extracting(
                InstitutionInviteTokenResponse.DomainResult::getOrganization,
                InstitutionInviteTokenResponse.DomainResult::getTransactionHash,
                InstitutionInviteTokenResponse.DomainResult::getError
            )
            .containsExactly(
                org.assertj.core.api.Assertions.tuple("example.edu", "0xabc", null),
                org.assertj.core.api.Assertions.tuple("another.edu", null, "Contract reverted")
            );
    }

    @Test
    void applyInviteRejectsMismatchedWallets() throws Exception {
        String token = buildToken(List.of("example.edu"), "0xabc");
        InstitutionInviteTokenRequest request = new InstitutionInviteTokenRequest();
        request.setToken(token);
        request.setWalletAddress("0xdef");

        assertThatThrownBy(() -> inviteService.applyInvite(request))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("different wallet address")
            .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
            .isEqualTo(HttpStatus.BAD_REQUEST);

        verify(diamond, never()).grantInstitutionRole(anyString(), anyString());
    }

    @Test
    void applyInviteValidatesSignature() {
        InstitutionInviteTokenRequest request = new InstitutionInviteTokenRequest();
        request.setToken("invalid.token");

        assertThatThrownBy(() -> inviteService.applyInvite(request))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Invalid invite signature length.");
    }

    private String buildToken(List<String> organizations, String institutionWallet) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("inviteId", "invite-123");
        payload.put("issuer", "marketplace");
        if (institutionWallet != null) {
            payload.put("institutionWallet", institutionWallet);
        }
        payload.put("organizations", organizations);

        ObjectMapper mapper = new ObjectMapper();
        byte[] json = mapper.writeValueAsBytes(payload);
        String payloadPart = Base64.getUrlEncoder().withoutPadding().encodeToString(json);
        String signature = hmac(payloadPart, HMAC_SECRET);
        return payloadPart + "." + signature;
    }

    private String hmac(String payload, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] result = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(result.length * 2);
        for (byte b : result) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }
}
