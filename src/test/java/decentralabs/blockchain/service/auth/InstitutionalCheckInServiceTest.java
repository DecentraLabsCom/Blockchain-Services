package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.identity.IdentityEvidenceDTO;
import decentralabs.blockchain.dto.identity.NormalizedClaims;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;

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

    private InstitutionalCheckInService service;
    private Credentials credentials;

    @BeforeEach
    void setUp() throws Exception {
        service = new InstitutionalCheckInService(
            samlValidationService,
            marketplaceEndpointAuthService,
            bookingService,
            institutionalWalletService,
            walletService,
            checkInVerifier,
            checkInOnChainService
        );
        ReflectionTestUtils.setField(service, "contractAddress", "0x1234567890abcdef1234567890abcdef12345678");
        credentials = Credentials.create(Keys.createEcKeyPair());
    }

    @Test
    void checkIn_prefersIdentityEvidenceWhenAvailable() throws Exception {
        String puc = "user@university.edu";
        String reservationKey = "0x" + "1".repeat(64);
        String institutionWallet = "0x1111111111111111111111111111111111111111";

        NormalizedClaims normalizedClaims = NormalizedClaims.builder()
            .stableUserId(puc)
            .institutionId("university.edu")
            .puc(puc)
            .build();
        IdentityEvidenceDTO identityEvidence = IdentityEvidenceDTO.builder()
            .type("saml")
            .normalizedClaims(normalizedClaims)
            .evidenceHash("0x" + "a".repeat(64))
            .build();

        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        request.setMarketplaceToken("marketplace-token");
        request.setIdentityEvidence(identityEvidence);
        request.setNormalizedClaims(normalizedClaims);
        request.setPuc(puc);
        request.setReservationKey(reservationKey);
        request.setInstitutionalProviderWallet(institutionWallet);

        when(marketplaceEndpointAuthService.enforceToken(eq("marketplace-token"), any()))
            .thenReturn(Map.of(
                "userid", puc,
                "affiliation", "university.edu",
                "puc", puc,
                "institutionalProviderWallet", institutionWallet
            ));
        when(bookingService.getBookingInfo(eq(institutionWallet), eq(reservationKey), isNull(), eq(puc)))
            .thenReturn(Map.of("reservationKey", reservationKey));
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(checkInVerifier.buildDigest(eq(credentials.getAddress()), eq(normalizeBytes32(reservationKey)), anyString(), anyLong()))
            .thenReturn(new byte[32]);
        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        response.setReservationKey(reservationKey);
        response.setSigner(credentials.getAddress());
        when(checkInOnChainService.verifyAndSubmit(any())).thenReturn(response);

        CheckInResponse result = service.checkIn(request);

        assertThat(result.isValid()).isTrue();
        assertThat(result.getReservationKey()).isEqualTo(reservationKey);
        assertThat(result.getSigner()).isEqualTo(credentials.getAddress());

        ArgumentCaptor<decentralabs.blockchain.dto.auth.CheckInRequest> captor =
            ArgumentCaptor.forClass(decentralabs.blockchain.dto.auth.CheckInRequest.class);
        verify(checkInOnChainService).verifyAndSubmit(captor.capture());
        assertThat(captor.getValue().getPuc()).isEqualTo(puc);
        assertThat(captor.getValue().getReservationKey()).isEqualTo(reservationKey);
        assertThat(captor.getValue().getSigner()).isEqualTo(credentials.getAddress());
        verify(samlValidationService, org.mockito.Mockito.never()).validateSamlAssertionDetailed(anyString());
    }

    @Test
    void checkIn_supportsLegacySamlFallback() throws Exception {
        String puc = "legacy-user@university.edu";
        String reservationKey = "0x" + "2".repeat(64);
        String institutionWallet = "0x2222222222222222222222222222222222222222";

        InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
        request.setMarketplaceToken("marketplace-token");
        request.setSamlAssertion("legacy-saml-assertion");
        request.setPuc(puc);
        request.setReservationKey(reservationKey);
        request.setInstitutionalProviderWallet(institutionWallet);

        when(samlValidationService.validateSamlAssertionDetailed("legacy-saml-assertion"))
            .thenReturn(new SamlAssertionAttributes(
                "issuer",
                puc,
                "university.edu",
                "legacy@university.edu",
                "Legacy User",
                List.of("university.edu"),
                Map.of()
            ));
        when(marketplaceEndpointAuthService.enforceToken(eq("marketplace-token"), any()))
            .thenReturn(Map.of(
                "userid", puc,
                "affiliation", "university.edu",
                "institutionalProviderWallet", institutionWallet
            ));
        when(bookingService.getBookingInfo(eq(institutionWallet), eq(reservationKey), isNull(), eq(puc)))
            .thenReturn(Map.of("reservationKey", reservationKey));
        when(institutionalWalletService.getInstitutionalCredentials()).thenReturn(credentials);
        when(checkInVerifier.buildDigest(eq(credentials.getAddress()), eq(normalizeBytes32(reservationKey)), anyString(), anyLong()))
            .thenReturn(new byte[32]);
        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        response.setReservationKey(reservationKey);
        response.setSigner(credentials.getAddress());
        when(checkInOnChainService.verifyAndSubmit(any())).thenReturn(response);

        CheckInResponse result = service.checkIn(request);

        assertThat(result.isValid()).isTrue();
        verify(samlValidationService).validateSamlAssertionDetailed("legacy-saml-assertion");
    }

    private String normalizeBytes32(String value) {
        String clean = value == null ? "" : value.replaceFirst("^0x", "");
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }
}
