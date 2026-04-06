package decentralabs.blockchain.service.wallet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.dto.wallet.BalanceResponse;
import decentralabs.blockchain.dto.wallet.EventListenerResponse;
import decentralabs.blockchain.dto.wallet.NetworkResponse;
import decentralabs.blockchain.dto.wallet.PayoutRequestSimulationResult;
import decentralabs.blockchain.dto.wallet.TransactionHistoryResponse;
import decentralabs.blockchain.dto.wallet.WalletImportRequest;
import decentralabs.blockchain.event.NetworkSwitchEvent;
import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.persistence.WalletPersistenceService;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Response;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthBlockNumber;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.ContractGasProvider;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("unchecked")
class WalletServiceTest {

    private static final String PRIVATE_KEY =
        "0x59c6995e998f97a5a0044966f0945389d2f5dc5b28d07f0bcdce5dab66f5d7bf";

    @Mock
    private WalletPersistenceService walletPersistenceService;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Mock
    private Web3j web3j;

    private WalletService service;

    @BeforeEach
    void setUp() {
        service = new WalletService(walletPersistenceService, eventPublisher);
        ReflectionTestUtils.setField(service, "mainnetRpcUrl", "https://main-a.example, https://main-b.example");
        ReflectionTestUtils.setField(service, "sepoliaRpcUrl", "https://sep-a.example, https://sep-b.example");
        ReflectionTestUtils.setField(service, "defaultNetwork", "sepolia");
        ReflectionTestUtils.setField(service, "contractAddress", "0x2222222222222222222222222222222222222222");
        ReflectionTestUtils.setField(service, "defaultWalletAddress", "0x1111111111111111111111111111111111111111");
    }

    @Test
    void init_parsesRpcUrlsAndSetsDefaults() {
        service.init();

        @SuppressWarnings("unchecked")
        Map<String, List<String>> networkRpcUrls =
            (Map<String, List<String>>) ReflectionTestUtils.getField(service, "networkRpcUrls");
        @SuppressWarnings("unchecked")
        Map<String, Integer> currentRpcIndex =
            (Map<String, Integer>) ReflectionTestUtils.getField(service, "currentRpcIndex");

        assertThat(networkRpcUrls).isNotNull();
        assertThat(networkRpcUrls.get("mainnet")).containsExactly("https://main-a.example", "https://main-b.example");
        assertThat(networkRpcUrls.get("sepolia")).containsExactly("https://sep-a.example", "https://sep-b.example");
        assertThat(currentRpcIndex).containsEntry("mainnet", 0).containsEntry("sepolia", 0);
        assertThat(ReflectionTestUtils.getField(service, "activeNetwork")).isEqualTo("sepolia");
        assertThat(ReflectionTestUtils.getField(service, "httpClient")).isNotNull();
    }

    @Test
    void createWallet_createsAndPersistsInstitutionalWallet() {
        when(walletPersistenceService.getCurrentWalletAddress()).thenReturn(null);

        var response = service.createWallet("strong-password");

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getAddress()).startsWith("0x");
        assertThat(response.getPrivateKey()).startsWith("0x");
        assertThat(response.getEncryptedPrivateKey()).isNotBlank();
        assertThat(response.getMessage()).contains("created successfully");
        verify(walletPersistenceService).saveWallet(response.getAddress(), response.getEncryptedPrivateKey());
    }

    @Test
    void createWallet_mentionsReplacementWhenWalletAlreadyExists() {
        when(walletPersistenceService.getCurrentWalletAddress()).thenReturn("0xold");

        var response = service.createWallet("strong-password");

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getMessage()).contains("replaced previous wallet 0xold");
    }

    @Test
    void importWallet_supportsPrivateKeyMnemonicAndValidationError() {
        when(walletPersistenceService.getCurrentWalletAddress()).thenReturn(null);

        WalletImportRequest privateKeyRequest = WalletImportRequest.builder()
            .privateKey(PRIVATE_KEY.substring(2))
            .password("strong-password")
            .build();
        var privateKeyResponse = service.importWallet(privateKeyRequest);
        assertThat(privateKeyResponse.isSuccess()).isTrue();
        assertThat(privateKeyResponse.getAddress()).startsWith("0x");
        assertThat(privateKeyResponse.getEncryptedPrivateKey()).isNotBlank();

        WalletImportRequest mnemonicRequest = WalletImportRequest.builder()
            .mnemonic("test test test test test test test test test test test junk")
            .password("another-strong-password")
            .build();
        var mnemonicResponse = service.importWallet(mnemonicRequest);
        assertThat(mnemonicResponse.isSuccess()).isTrue();
        assertThat(mnemonicResponse.getAddress()).startsWith("0x");

        WalletImportRequest invalidRequest = WalletImportRequest.builder()
            .password("another-strong-password")
            .build();
        var invalidResponse = service.importWallet(invalidRequest);
        assertThat(invalidResponse.isSuccess()).isFalse();
        assertThat(invalidResponse.getError()).contains("Either privateKey or mnemonic");
    }

    @Test
    void revealInstitutionalPrivateKey_returnsPrivateKeyWhenPasswordMatches() {
        String encrypted = ReflectionTestUtils.invokeMethod(service, "encryptPrivateKey", PRIVATE_KEY, "secret");
        when(walletPersistenceService.getCurrentWalletAddress()).thenReturn("0xabc");
        when(walletPersistenceService.getWallet("0xabc")).thenReturn(encrypted);

        var response = service.revealInstitutionalPrivateKey("secret");

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getAddress()).isEqualTo("0xabc");
        assertThat(response.getPrivateKey()).isEqualTo(PRIVATE_KEY);
    }

    @Test
    void revealInstitutionalPrivateKey_rejectsMissingWalletOrWrongPassword() {
        when(walletPersistenceService.getCurrentWalletAddress()).thenReturn(" ");

        var missingResponse = service.revealInstitutionalPrivateKey("secret");

        assertThat(missingResponse.isSuccess()).isFalse();
        assertThat(missingResponse.getError()).contains("not configured");

        String encrypted = ReflectionTestUtils.invokeMethod(service, "encryptPrivateKey", PRIVATE_KEY, "secret");
        when(walletPersistenceService.getCurrentWalletAddress()).thenReturn("0xabc");
        when(walletPersistenceService.getWallet("0xabc")).thenReturn(encrypted);

        var invalidResponse = service.revealInstitutionalPrivateKey("wrong");

        assertThat(invalidResponse.isSuccess()).isFalse();
        assertThat(invalidResponse.getError()).contains("Invalid password");
    }

    @Test
    void getBalance_returnsEthBalanceAndServiceCredits() throws Exception {
        WalletService spyService = spy(service);
        String walletAddress = "0x1111111111111111111111111111111111111111";
        ReflectionTestUtils.setField(spyService, "activeNetwork", "sepolia");
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubGetBalance(walletAddress, BigInteger.ONE);
        stubEthCalls(
            web3j,
            ethCallResponse(encodeValues(new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(1_500_000))))
        );

        BalanceResponse response = spyService.getBalance(walletAddress);

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getBalanceWei()).isEqualTo("1");
        assertThat(response.getBalanceEth()).isEqualTo("1E-18");
        assertThat(response.getLabTokenAddress()).isEqualTo("0x2222222222222222222222222222222222222222");
        assertThat(response.getLabBalanceRaw()).isEqualTo("1500000");
        assertThat(response.getLabBalance()).isEqualTo("15");
        assertThat(response.getNetwork()).isEqualTo("sepolia");
    }

    @Test
    void getBalance_returnsErrorWhenRpcFails() {
        WalletService spyService = spy(service);
        org.mockito.Mockito.doThrow(new RuntimeException("rpc down")).when(spyService).getWeb3jInstance();

        BalanceResponse response = spyService.getBalance("0xwallet");

        assertThat(response.isSuccess()).isFalse();
        assertThat(response.getError()).contains("rpc down");
    }

    @Test
    void labTokenAndErc20Helpers_decodeAndCacheValues() throws Exception {
        WalletService spyService = spy(service);
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(web3j, ethCallResponse(encodeValues(new Address("0x3333333333333333333333333333333333333333"))));

        String tokenAddress = ReflectionTestUtils.invokeMethod(spyService, "getLabTokenAddress");

        assertThat(tokenAddress).isEqualTo("0x3333333333333333333333333333333333333333");
        assertThat(ReflectionTestUtils.getField(spyService, "cachedLabTokenAddress"))
            .isEqualTo("0x3333333333333333333333333333333333333333");

        org.mockito.Mockito.reset(web3j);
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(
            web3j,
            ethCallResponse(encodeValues(new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(12_500_000))))
        );

        BigInteger tokenBalance = ReflectionTestUtils.invokeMethod(
            spyService,
            "getERC20Balance",
            "0x1111111111111111111111111111111111111111",
            "0x3333333333333333333333333333333333333333"
        );

        assertThat(tokenBalance).isEqualTo(BigInteger.valueOf(12_500_000));
    }

    @Test
    void getTransactionHistory_returnsCountAndHandlesErrors() throws Exception {
        WalletService spyService = spy(service);
        ReflectionTestUtils.setField(spyService, "activeNetwork", "sepolia");
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubTransactionCount("0xwallet", BigInteger.valueOf(7));

        TransactionHistoryResponse success = spyService.getTransactionHistory("0xwallet");

        assertThat(success.isSuccess()).isTrue();
        assertThat(success.getTransactionCount()).isEqualTo("7");
        assertThat(success.getTransactions()).isEmpty();
        assertThat(success.getNetwork()).isEqualTo("sepolia");

        org.mockito.Mockito.doThrow(new RuntimeException("history down")).when(spyService).getWeb3jInstance();
        TransactionHistoryResponse failure = spyService.getTransactionHistory("0xwallet");

        assertThat(failure.isSuccess()).isFalse();
        assertThat(failure.getError()).contains("history down");
    }

    @Test
    void getEventListenerStatus_returnsConfiguredSnapshot() {
        ReflectionTestUtils.setField(service, "activeNetwork", "mainnet");

        EventListenerResponse response = service.getEventListenerStatus();

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getContractAddress()).isEqualTo("0x2222222222222222222222222222222222222222");
        assertThat(response.getNetwork()).isEqualTo("mainnet");
        assertThat(response.getMessage()).contains("configured automatically");
    }

    @Test
    void getAvailableNetworks_andSwitchNetwork_publishExpectedState() {
        service.init();

        NetworkResponse before = service.getAvailableNetworks();

        assertThat(before.isSuccess()).isTrue();
        assertThat(before.getActiveNetwork()).isEqualTo("sepolia");
        assertThat(before.getNetworks()).hasSize(2);
        assertThat(before.getNetworks().get(0).getRpcUrl()).contains("https://main-a.example,https://main-b.example");

        NetworkResponse invalid = service.switchNetwork("invalid");
        assertThat(invalid.isSuccess()).isFalse();
        verifyNoInteractions(eventPublisher);

        NetworkResponse switched = service.switchNetwork("mainnet");

        assertThat(switched.isSuccess()).isTrue();
        assertThat(switched.getActiveNetwork()).isEqualTo("mainnet");
        ArgumentCaptor<NetworkSwitchEvent> captor = ArgumentCaptor.forClass(NetworkSwitchEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());
        NetworkSwitchEvent event = captor.getValue();
        assertThat(event.getOldNetwork()).isEqualTo("sepolia");
        assertThat(event.getNewNetwork()).isEqualTo("mainnet");
    }

    @Test
    void contractViewMethods_decodeExpectedValues() throws Exception {
        WalletService spyService = spy(service);
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(
            web3j,
            ethCallResponse(encodeValues(new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(50)))),
            ethCallResponse(encodeValues(new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(3600)))),
            ethCallResponse(encodeValues(new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(9000)))),
            ethCallResponse(encodeValues(new Bool(true)))
        );

        assertThat(spyService.getInstitutionalUserLimit("0x1111111111111111111111111111111111111111"))
            .isEqualTo(BigInteger.valueOf(50));
        assertThat(spyService.getInstitutionalSpendingPeriod("0x1111111111111111111111111111111111111111"))
            .isEqualTo(BigInteger.valueOf(3600));
        assertThat(spyService.getInstitutionalBillingBalance("0x1111111111111111111111111111111111111111"))
            .isEqualTo(BigInteger.valueOf(9000));
        assertThat(spyService.isLabProvider("0x1111111111111111111111111111111111111111")).isTrue();
    }

    @Test
    void getServiceCreditBalance_returnsZeroWhenRpcErrors() throws Exception {
        WalletService spyService = spy(service);
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(web3j, ethCallError("boom"));

        assertThat(spyService.getServiceCreditBalance("0x1111111111111111111111111111111111111111"))
            .isEqualTo(BigInteger.ZERO);
    }

    @Test
    void providerAssociationAndTokenGuards_coverOwnershipAndValidation() throws Exception {
        WalletService spyService = spy(service);
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(web3j, ethCallResponse(encodeValues(new Address("0x1111111111111111111111111111111111111111"))));

        assertThat(spyService.isLabOwnedByProvider("0x1111111111111111111111111111111111111111", BigInteger.ONE)).isTrue();
        assertThat(spyService.isLabOwnedByProvider(" ", BigInteger.ONE)).isFalse();
        assertThat(spyService.isLabOwnedByProvider("0x1111111111111111111111111111111111111111", BigInteger.ZERO)).isFalse();
        assertThat(spyService.getLabTokenUri(BigInteger.ZERO)).isEqualTo(Optional.empty());
        assertThat((String) ReflectionTestUtils.invokeMethod(spyService, "normalizeUri", " https://example.test/path/// "))
            .isEqualTo("https://example.test/path");
    }

    @SuppressWarnings("unchecked")
    @Test
    void getLabsOwnedByProvider_returnsOnlyDirectOwnership() throws Exception {
        WalletService spyService = spy(service);
        String provider = "0x1111111111111111111111111111111111111111";
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(
            web3j,
            ethCallResponse("0x1"),
            ethCallResponse("0x2"),
            ethCallResponse("0x3"),
            ethCallResponse("0x4")
        );

        try (MockedStatic<FunctionReturnDecoder> decoder = org.mockito.Mockito.mockStatic(FunctionReturnDecoder.class)) {
            decoder.when(() -> FunctionReturnDecoder.decode(any(String.class), any(List.class))).thenReturn(
                List.of(
                    new DynamicArray<>(org.web3j.abi.datatypes.generated.Uint256.class, List.of(
                        new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(3)),
                        new org.web3j.abi.datatypes.generated.Uint256(BigInteger.ONE),
                        new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(2))
                    )),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(3))
                ),
                List.of(new Address(provider)),
                List.of(new Address(provider)),
                List.of(new Address("0x9999999999999999999999999999999999999999"))
            );

            assertThat(spyService.getLabsOwnedByProvider(provider))
                .containsExactly(BigInteger.ONE, BigInteger.valueOf(2));
        }
    }

    @Test
    void isLabOwnedByProvider_returnsFalseWhenOwnerDoesNotMatch() throws Exception {
        WalletService spyService = spy(service);
        String provider = "0x1111111111111111111111111111111111111111";
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(web3j, ethCallResponse("0x1"));

        try (MockedStatic<FunctionReturnDecoder> decoder = org.mockito.Mockito.mockStatic(FunctionReturnDecoder.class)) {
            decoder.when(() -> FunctionReturnDecoder.decode(any(String.class), any(List.class)))
                .thenReturn(List.of(new Address("0x9999999999999999999999999999999999999999")));

            assertThat(spyService.isLabOwnedByProvider(provider, BigInteger.valueOf(7))).isFalse();
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    void getLabTokenUri_prefersTokenUriAndFallsBackToDiamondBaseUri() throws Exception {
        WalletService spyService = spy(service);
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(web3j, ethCallResponse("0x1"), ethCallError("tokenURI failed"));

        try (
            MockedStatic<FunctionReturnDecoder> decoder = org.mockito.Mockito.mockStatic(FunctionReturnDecoder.class);
            MockedStatic<Diamond> diamondStatic = org.mockito.Mockito.mockStatic(Diamond.class)
        ) {
            Diamond diamond = mock(Diamond.class);
            RemoteFunctionCall<Diamond.Lab> remoteCall = mock(RemoteFunctionCall.class);
            diamondStatic.when(() -> Diamond.load(
                any(String.class),
                eq(web3j),
                any(TransactionManager.class),
                any(ContractGasProvider.class)
            )).thenReturn(diamond);
            when(diamond.getLab(BigInteger.valueOf(2))).thenReturn(remoteCall);
            when(remoteCall.send()).thenReturn(
                new Diamond.Lab(
                    BigInteger.valueOf(2),
                    new Diamond.LabBase("  ipfs://fallback-uri  ", BigInteger.ZERO, "", "", BigInteger.ZERO)
                )
            );
            decoder.when(() -> FunctionReturnDecoder.decode(any(String.class), any(List.class))).thenReturn(
                List.of(new Utf8String("ipfs://token-uri"))
            );

            assertThat(spyService.getLabTokenUri(BigInteger.ONE)).contains("ipfs://token-uri");
            assertThat(spyService.getLabTokenUri(BigInteger.valueOf(2))).contains("ipfs://fallback-uri");
        }
    }

    @Test
    void payoutSimulationAndStats_coverSuccessAndGuards() throws Exception {
        WalletService spyService = spy(service);
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(
            web3j,
            ethCallResponse(
                encodeValues(
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.ONE),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.TWO),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(3)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(4))
                )
            ),
            ethCallResponse(
                encodeValues(
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(21)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(22)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(23)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(24)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(25)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(26)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(27)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(28))
                )
            ),
            ethCallResponse("0x"),
            ethCallResponse(
                encodeValues(
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(7)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(8)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(9)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(10)),
                    new Bool(true)
                )
            ),
            ethCallResponse(
                encodeValues(
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(11)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(12)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(13)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(14)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(15)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(16)),
                    new org.web3j.abi.datatypes.generated.Uint256(BigInteger.valueOf(17))
                )
            )
        );

        var receivableStatus = spyService.getProviderReceivableStatus(BigInteger.ONE);
        PayoutRequestSimulationResult collect = spyService.simulateProviderPayoutRequest(
            "0x1111111111111111111111111111111111111111",
            BigInteger.ONE,
            BigInteger.TEN
        );
        var stakeInfo = spyService.getStakeInfo("0x1111111111111111111111111111111111111111");
        var financialStats = spyService.getInstitutionalUserFinancialStats(
            "0x1111111111111111111111111111111111111111",
            "PUC-1"
        );

        assertThat(receivableStatus).isPresent();
        assertThat(receivableStatus.get().providerReceivable()).isEqualTo(BigInteger.ONE);
        assertThat(receivableStatus.get().accruedReceivable()).isEqualTo(BigInteger.valueOf(21));
        assertThat(receivableStatus.get().settlementQueued()).isEqualTo(BigInteger.valueOf(22));
        assertThat(receivableStatus.get().invoicedReceivable()).isEqualTo(BigInteger.valueOf(23));
        assertThat(receivableStatus.get().approvedReceivable()).isEqualTo(BigInteger.valueOf(24));
        assertThat(receivableStatus.get().paidReceivable()).isEqualTo(BigInteger.valueOf(25));
        assertThat(receivableStatus.get().reversedReceivable()).isEqualTo(BigInteger.valueOf(26));
        assertThat(receivableStatus.get().disputedReceivable()).isEqualTo(BigInteger.valueOf(27));
        assertThat(receivableStatus.get().lastAccruedAt()).isEqualTo(BigInteger.valueOf(28));
        assertThat(collect.canRequestPayout()).isTrue();
        assertThat(stakeInfo.getStakedAmount()).isEqualTo(BigInteger.valueOf(7));
        assertThat(stakeInfo.isCanUnstake()).isTrue();
        assertThat(financialStats).isPresent();
        assertThat(financialStats.get().getRemainingAllowance()).isEqualTo(BigInteger.valueOf(14));
        assertThat(spyService.simulateProviderPayoutRequest(" ", BigInteger.ONE, BigInteger.TEN).canRequestPayout()).isFalse();
    }

    @Test
    void internalHelpers_coverSanitizationAndErrorFallbacks() throws Exception {
        WalletService spyService = spy(service);
        org.mockito.Mockito.doReturn(web3j).when(spyService).getWeb3jInstance();
        stubEthCalls(
            web3j,
            ethCallError("execution reverted: collect disabled"),
            ethCallError("boom"),
            ethCallError("boom"),
            ethCallError("boom"),
            ethCallError("boom")
        );

        assertThat((String) ReflectionTestUtils.invokeMethod(spyService, "sanitizeRpcMessage", (String) null))
            .isEqualTo("Payout request reverted");
        assertThat((String) ReflectionTestUtils.invokeMethod(spyService, "sanitizeRpcMessage", "execution reverted: denied"))
            .isEqualTo("denied");
        assertThat((String) ReflectionTestUtils.invokeMethod(spyService, "decodeRevertReason", "0x1234")).isNull();

        PayoutRequestSimulationResult failedCollect = spyService.simulateProviderPayoutRequest(
            "0x1111111111111111111111111111111111111111",
            BigInteger.ONE,
            BigInteger.ONE
        );
        assertThat(failedCollect.canRequestPayout()).isFalse();
        assertThat(failedCollect.reason()).isEqualTo("collect disabled");
        assertThat(spyService.getInstitutionalUserLimit("0x1111111111111111111111111111111111111111")).isNull();
        assertThat(spyService.getInstitutionalBillingBalance("0x1111111111111111111111111111111111111111")).isNull();
        assertThat(spyService.getStakeInfo("0x1111111111111111111111111111111111111111").getStakedAmount()).isEqualTo(BigInteger.ZERO);
        assertThat(spyService.getInstitutionalUserFinancialStats("0x1111111111111111111111111111111111111111", "PUC")).isEmpty();
    }

    @Test
    void getWeb3jInstanceWithFallback_switchesToHealthyFallbackAndUpdatesIndex() throws Exception {
        service.init();
        @SuppressWarnings("unchecked")
        Map<String, Web3j> web3jInstances =
            (Map<String, Web3j>) ReflectionTestUtils.getField(service, "web3jInstances");
        @SuppressWarnings("unchecked")
        Map<String, Integer> currentRpcIndex =
            (Map<String, Integer>) ReflectionTestUtils.getField(service, "currentRpcIndex");
        Web3j failing = mock(Web3j.class);
        Web3j healthy = mock(Web3j.class);
        web3jInstances.put("sepolia:0", failing);
        web3jInstances.put("sepolia:1", healthy);
        currentRpcIndex.put("sepolia", 0);
        stubBlockNumber(failing, new RuntimeException("rpc-0 down"));
        stubBlockNumber(healthy, 123L);

        Web3j result = ReflectionTestUtils.invokeMethod(service, "getWeb3jInstanceWithFallback", "sepolia");

        assertThat(result).isSameAs(healthy);
        assertThat(currentRpcIndex.get("sepolia")).isEqualTo(1);
        assertThat(web3jInstances).doesNotContainKey("sepolia:0");
    }

    @Test
    void getWeb3jInstanceWithFallback_throwsWhenAllEndpointsFail() throws Exception {
        service.init();
        @SuppressWarnings("unchecked")
        Map<String, Web3j> web3jInstances =
            (Map<String, Web3j>) ReflectionTestUtils.getField(service, "web3jInstances");
        Web3j first = mock(Web3j.class);
        Web3j second = mock(Web3j.class);
        web3jInstances.put("sepolia:0", first);
        web3jInstances.put("sepolia:1", second);
        stubBlockNumber(first, new RuntimeException("rpc-0 down"));
        stubBlockNumber(second, new RuntimeException("rpc-1 down"));

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "getWeb3jInstanceWithFallback", "sepolia"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("All RPC endpoints failed for network: sepolia");
    }

    @Test
    void getWeb3jInstanceForNetwork_fallsBackForBlankOrUnknownNetwork() {
        WalletService spyService = spy(service);
        Web3j expected = mock(Web3j.class);
        org.mockito.Mockito.doReturn(expected).when(spyService).getWeb3jInstance();

        assertThat(spyService.getWeb3jInstanceForNetwork(" ")).isSameAs(expected);
        assertThat(spyService.getWeb3jInstanceForNetwork("unknown")).isSameAs(expected);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubGetBalance(String address, BigInteger balance) throws Exception {
        Request request = mock(Request.class);
        EthGetBalance response = new EthGetBalance();
        response.setResult("0x" + balance.toString(16));
        when(web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST)).thenReturn(request);
        when(request.send()).thenReturn(response);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubTransactionCount(String address, BigInteger count) throws Exception {
        Request request = mock(Request.class);
        EthGetTransactionCount response = new EthGetTransactionCount();
        response.setResult("0x" + count.toString(16));
        when(web3j.ethGetTransactionCount(address, DefaultBlockParameterName.LATEST)).thenReturn(request);
        when(request.send()).thenReturn(response);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubBlockNumber(Web3j target, long blockNumber) throws Exception {
        Request request = mock(Request.class);
        EthBlockNumber response = new EthBlockNumber();
        response.setResult("0x" + Long.toHexString(blockNumber));
        when(target.ethBlockNumber()).thenReturn(request);
        when(request.send()).thenReturn(response);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void stubBlockNumber(Web3j target, RuntimeException error) throws Exception {
        Request request = mock(Request.class);
        when(target.ethBlockNumber()).thenReturn(request);
        when(request.send()).thenThrow(error);
    }

    @SuppressWarnings({"unchecked"})
    private void stubEthCalls(Web3j target, EthCall... responses) throws Exception {
        Request<?, EthCall>[] requests = new Request[responses.length];
        for (int i = 0; i < responses.length; i++) {
            requests[i] = (Request<?, EthCall>) mock(Request.class);
            when(requests[i].send()).thenReturn(responses[i]);
        }
        AtomicInteger index = new AtomicInteger();
        when(target.ethCall(any(org.web3j.protocol.core.methods.request.Transaction.class), eq(DefaultBlockParameterName.LATEST)))
            .thenAnswer(invocation -> requests[Math.min(index.getAndIncrement(), requests.length - 1)]);
    }

    private EthCall ethCallResponse(String value) {
        EthCall response = new EthCall();
        response.setResult(value);
        return response;
    }

    private EthCall ethCallError(String message) {
        EthCall response = new EthCall();
        response.setError(new Response.Error(1, message));
        return response;
    }

    private String encodeValues(Type<?>... types) {
        return "0x" + Arrays.stream(types).map(TypeEncoder::encode).collect(Collectors.joining());
    }
}
