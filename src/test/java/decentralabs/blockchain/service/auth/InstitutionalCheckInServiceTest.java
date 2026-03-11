package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

@ExtendWith(MockitoExtension.class)
class InstitutionalCheckInServiceTest {

    @Mock
    private SamlValidationService samlValidationService;

    @Mock
    private MarketplaceEndpointAuthService marketplaceEndpointAuthService;

    @Mock
    private BlockchainBookingService bookingService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private WalletService walletService;

    @Mock
    private Eip712CheckInVerifier checkInVerifier;

    @Mock
    private CheckInOnChainService checkInOnChainService;

    @InjectMocks
    private InstitutionalCheckInService service;

    private Credentials credentials;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "contractAddress", "0x2222222222222222222222222222222222222222");
        credentials = Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");
    }

    @Test
    void checkInShouldBuildSignedRequestAndSubmitIt() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        SamlAssertionAttributes saml = samlAttributes();
        byte[] digest = Hash.sha3("institutional-checkin".getBytes(StandardCharsets.UTF_8));
        CheckInResponse onChainResponse = new CheckInResponse();
        onChainResponse.setValid(true);
        onChainResponse.setTxHash("0xtx123");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(saml);
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(Map.of(
            "userid", "user-1",
            "affiliation", "org.example",
            "puc", "puc-123",
            "institutionalProviderWallet", "0x1111111111111111111111111111111111111111"
        ));
        when(bookingService.getBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "puc-123"))
            .thenReturn(Map.of("reservationKey", "0xabc"));
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(checkInVerifier.buildDigest(eq(credentials.getAddress()), eq(normalizeBytes32("0xabc")), eq(computePucHash("puc-123")), any(Long.class)))
            .thenReturn(digest);
        when(checkInOnChainService.verifyAndSubmit(any(CheckInRequest.class))).thenReturn(onChainResponse);

        CheckInResponse response = service.checkIn(request);

        assertThat(response).isSameAs(onChainResponse);
        verify(bookingService).getBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "puc-123");

        ArgumentCaptor<CheckInRequest> captor = ArgumentCaptor.forClass(CheckInRequest.class);
        verify(checkInOnChainService).verifyAndSubmit(captor.capture());
        CheckInRequest checkInRequest = captor.getValue();

        assertThat(checkInRequest.getReservationKey()).isEqualTo("0xabc");
        assertThat(checkInRequest.getSigner()).isEqualTo(credentials.getAddress());
        assertThat(checkInRequest.getPuc()).isEqualTo("puc-123");
        assertThat(checkInRequest.getTimestamp()).isNotNull();
        assertThat(checkInRequest.getSignature()).isEqualTo(signatureToHex(Sign.signMessage(digest, credentials.getEcKeyPair(), false)));
    }

    @Test
    void checkInShouldRejectRequestPucMismatch() throws Exception {
        InstitutionalCheckInRequest request = validRequest();
        request.setPuc("other-puc");

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(Map.of(
            "userid", "user-1",
            "affiliation", "org.example",
            "puc", "puc-123"
        ));

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("Request puc does not match authenticated user");
    }

    @Test
    void checkInShouldRejectMarketplaceInstitutionWalletMismatch() throws Exception {
        InstitutionalCheckInRequest request = validRequest();

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(Map.of(
            "userid", "user-1",
            "affiliation", "org.example",
            "puc", "puc-123",
            "institutionalProviderWallet", "0x9999999999999999999999999999999999999999"
        ));

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("institutionalProviderWallet mismatch");
    }

    @Test
    void checkInShouldRejectMissingResolvedReservationKey() throws Exception {
        InstitutionalCheckInRequest request = validRequest();

        when(samlValidationService.validateSamlAssertionDetailed("valid-saml")).thenReturn(samlAttributes());
        when(marketplaceEndpointAuthService.enforceToken("market-token", null)).thenReturn(Map.of(
            "userid", "user-1",
            "affiliation", "org.example",
            "puc", "puc-123",
            "institutionalProviderWallet", "0x1111111111111111111111111111111111111111"
        ));
        when(bookingService.getBookingInfo("0x1111111111111111111111111111111111111111", "0xabc", "42", "puc-123"))
            .thenReturn(Map.of());

        assertThatThrownBy(() -> service.checkIn(request))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Reservation key could not be resolved");
    }

    private InstitutionalCheckInRequest validRequest() {
        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        request.setMarketplaceToken("market-token");
        request.setSamlAssertion("valid-saml");
        request.setReservationKey("0xabc");
        request.setLabId("42");
        request.setInstitutionalProviderWallet("0x1111111111111111111111111111111111111111");
        return request;
    }

    private SamlAssertionAttributes samlAttributes() {
        return new SamlAssertionAttributes(
            "issuer",
            "user-1",
            "org.example",
            "user@example.org",
            "User Example",
            List.of("org.example"),
            Map.of()
        );
    }

    private static String computePucHash(String puc) {
        byte[] hash = Hash.sha3(puc.getBytes(StandardCharsets.UTF_8));
        return normalizeBytes32(Numeric.toHexString(hash));
    }

    private static String normalizeBytes32(String value) {
        String clean = Numeric.cleanHexPrefix(value == null ? "" : value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }

    private static String signatureToHex(Sign.SignatureData signatureData) {
        byte[] sigBytes = new byte[65];
        System.arraycopy(signatureData.getR(), 0, sigBytes, 0, 32);
        System.arraycopy(signatureData.getS(), 0, sigBytes, 32, 32);
        sigBytes[64] = signatureData.getV()[0];
        return Numeric.toHexString(sigBytes);
    }
}
