package decentralabs.blockchain.service.treasury;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.treasury.InstitutionalReservationRequest;
import decentralabs.blockchain.service.auth.MarketplaceKeyService;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import io.jsonwebtoken.Jwts;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.LocalDateTime;
import java.time.Month;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class InstitutionalReservationServiceTest {

    @Mock
    private MarketplaceKeyService marketplaceKeyService;
    @Mock
    private SamlValidationService samlValidationService;
    @Mock
    private InstitutionalWalletService institutionalWalletService;
    @Mock
    private Web3j web3j;

    private InstitutionalReservationService reservationService;

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        reservationService = new InstitutionalReservationService(
            marketplaceKeyService,
            samlValidationService,
            institutionalWalletService,
            web3j
        );
        ReflectionTestUtils.setField(reservationService, "contractAddress", "0xABC");
        ReflectionTestUtils.setField(reservationService, "defaultGasPriceGwei", BigDecimal.ONE);
        ReflectionTestUtils.setField(reservationService, "contractGasLimit", BigInteger.valueOf(300_000));

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    @Test
    void processReservationExecutesBlockchainRequestAfterValidations() throws Exception {
        InstitutionalReservationRequest request = sampleRequest();
        String jwt = buildMarketplaceToken(request.getUserId(), request.getInstitutionId());
        request.setMarketplaceToken(jwt);
        request.setSamlAssertion("saml");

        when(marketplaceKeyService.getPublicKey(false)).thenReturn(keyPair.getPublic());
        when(samlValidationService.validateSamlAssertionWithSignature("saml"))
            .thenReturn(Map.of("userid", request.getUserId(), "affiliation", request.getInstitutionId()));
        when(institutionalWalletService.getInstitutionalCredentials())
            .thenReturn(Credentials.create("0x1"));

        Diamond contract = mock(Diamond.class);
        @SuppressWarnings("unchecked")
        RemoteFunctionCall<TransactionReceipt> functionCall = mock(RemoteFunctionCall.class);
        TransactionReceipt receipt = new TransactionReceipt();
        receipt.setTransactionHash("0xhash");
        when(functionCall.send()).thenReturn(receipt);
        when(contract.institutionalReservationRequest(
            any(), any(), any(), any(), any()
        )).thenReturn(functionCall);

        try (MockedStatic<Diamond> diamondMock = mockStatic(Diamond.class)) {
            diamondMock.when(() -> Diamond.load(eq("0xABC"), eq(web3j), any(Credentials.class), any()))
                .thenReturn(contract);

            Map<String, Object> response = reservationService.processReservation(request);

            assertThat(response)
                .containsEntry("success", true)
                .containsEntry("transactionHash", "0xhash")
                .containsEntry("userId", request.getUserId());
        }
    }

    @Test
    void processReservationFailsWhenJwtAndSamlDoNotMatch() throws Exception {
        InstitutionalReservationRequest request = sampleRequest();
        String jwt = buildMarketplaceToken("user-x", "another-institution");
        request.setMarketplaceToken(jwt);
        request.setSamlAssertion("saml");

        when(marketplaceKeyService.getPublicKey(false)).thenReturn(keyPair.getPublic());
        when(samlValidationService.validateSamlAssertionWithSignature("saml"))
            .thenReturn(Map.of("userid", request.getUserId(), "affiliation", request.getInstitutionId()));

        assertThatThrownBy(() -> reservationService.processReservation(request))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Authentication validation failed");
    }

    private InstitutionalReservationRequest sampleRequest() {
        return InstitutionalReservationRequest.builder()
            .marketplaceToken("temp")
            .samlAssertion("saml")
            .userId("user-123")
            .institutionId("institution-1")
            .labId(BigInteger.TWO)
            .startTime(LocalDateTime.of(2024, Month.JANUARY, 10, 12, 0))
            .endTime(LocalDateTime.of(2024, Month.JANUARY, 10, 14, 0))
            .userCount(1)
            .timestamp(System.currentTimeMillis())
            .build();
    }

    private String buildMarketplaceToken(String userId, String affiliation) {
        return Jwts.builder()
            .claim("userid", userId)
            .claim("affiliation", affiliation)
            .signWith(keyPair.getPrivate())
            .compact();
    }
}
