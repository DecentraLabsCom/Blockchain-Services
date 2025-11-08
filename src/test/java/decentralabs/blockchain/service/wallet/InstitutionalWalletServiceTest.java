package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.service.persistence.WalletPersistenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.crypto.Credentials;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class InstitutionalWalletServiceTest {

    private static final String PRIVATE_KEY =
        "0x59c6995e998f97a5a0044966f0945389d2f5dc5b28d07f0bcdce5dab66f5d7bf";
    private static final Credentials CREDENTIALS = Credentials.create(PRIVATE_KEY);

    @Mock
    private WalletService walletService;

    @Mock
    private WalletPersistenceService persistenceService;

    private InstitutionalWalletService institutionalWalletService;

    @BeforeEach
    void setUp() {
        institutionalWalletService = new InstitutionalWalletService(walletService, persistenceService);
        ReflectionTestUtils.setField(institutionalWalletService, "institutionalWalletAddress", CREDENTIALS.getAddress());
        ReflectionTestUtils.setField(institutionalWalletService, "institutionalWalletPassword", "secret");
    }

    @Test
    void initializeInstitutionalWalletShouldValidatePresence() {
        when(persistenceService.getWallet(CREDENTIALS.getAddress())).thenReturn("encrypted");

        institutionalWalletService.initializeInstitutionalWallet();

        verify(persistenceService).getWallet(CREDENTIALS.getAddress());
        verifyNoInteractions(walletService);
    }

    @Test
    void initializeInstitutionalWalletThrowsWhenWalletMissing() {
        when(persistenceService.getWallet(CREDENTIALS.getAddress())).thenReturn(null);

        assertThatThrownBy(() -> institutionalWalletService.initializeInstitutionalWallet())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Institutional wallet not found");
    }

    @Test
    void getInstitutionalCredentialsDecryptsAndCaches() {
        when(persistenceService.getWallet(CREDENTIALS.getAddress())).thenReturn("encrypted");
        when(walletService.decryptPrivateKey("encrypted", "secret")).thenReturn(PRIVATE_KEY);

        Credentials firstCall = institutionalWalletService.getInstitutionalCredentials();
        Credentials secondCall = institutionalWalletService.getInstitutionalCredentials();

        assertThat(firstCall.getAddress()).isEqualTo(CREDENTIALS.getAddress());
        assertThat(secondCall).isSameAs(firstCall);
        verify(persistenceService, times(1)).getWallet(CREDENTIALS.getAddress());
        verify(walletService, times(1)).decryptPrivateKey("encrypted", "secret");
    }

    @Test
    void getInstitutionalCredentialsFailsWhenAddressMismatch() {
        ReflectionTestUtils.setField(institutionalWalletService, "institutionalWalletAddress", "0x123");
        when(persistenceService.getWallet("0x123")).thenReturn("encrypted");
        when(walletService.decryptPrivateKey("encrypted", "secret")).thenReturn(PRIVATE_KEY);

        assertThatThrownBy(() -> institutionalWalletService.getInstitutionalCredentials())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("does not match configured address");
    }

    @Test
    void clearCredentialsCacheForcesReDecryptOnNextUse() {
        when(persistenceService.getWallet(CREDENTIALS.getAddress())).thenReturn("encrypted");
        when(walletService.decryptPrivateKey("encrypted", "secret")).thenReturn(PRIVATE_KEY);

        institutionalWalletService.getInstitutionalCredentials();
        institutionalWalletService.clearCredentialsCache();
        institutionalWalletService.getInstitutionalCredentials();

        verify(walletService, times(2)).decryptPrivateKey("encrypted", "secret");
    }

    @Test
    void isConfiguredReturnsTrueOnlyWhenWalletPresent() {
        when(persistenceService.getWallet(CREDENTIALS.getAddress())).thenReturn("encrypted");
        assertThat(institutionalWalletService.isConfigured()).isTrue();

        when(persistenceService.getWallet(CREDENTIALS.getAddress())).thenReturn(null);
        assertThat(institutionalWalletService.isConfigured()).isFalse();
    }
}
