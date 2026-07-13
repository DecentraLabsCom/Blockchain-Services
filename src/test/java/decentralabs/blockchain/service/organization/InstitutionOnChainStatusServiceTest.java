package decentralabs.blockchain.service.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class InstitutionOnChainStatusServiceTest {
    @Mock WalletService walletService;
    @Mock InstitutionalWalletService institutionalWalletService;

    @Test
    void shouldReportFullyOperationalOnlyWhenContractStateMatchesLocalConfiguration() {
        String wallet = "0x00000000000000000000000000000000000000aa";
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(wallet);
        when(walletService.isLabProvider(wallet)).thenReturn(true);
        when(walletService.isInstitution(wallet)).thenReturn(true);
        when(walletService.resolveInstitutionWalletForOrganization("uni.example")).thenReturn(wallet);
        when(walletService.getOrganizationBackendUrl("uni.example")).thenReturn("https://gateway.uni.example/");
        when(walletService.getAuthorizedInstitutionalBackend(wallet)).thenReturn(wallet);
        when(walletService.getProviderNetworkStatus(wallet)).thenReturn(1);

        InstitutionOnChainStatusService.Status status =
            new InstitutionOnChainStatusService(walletService, institutionalWalletService)
                .inspect("uni.example", "https://gateway.uni.example", true);

        assertThat(status.onChainStatusAvailable()).isTrue();
        assertThat(status.providerRoleOnChain()).isTrue();
        assertThat(status.institutionRoleOnChain()).isTrue();
        assertThat(status.organizationOwner()).isEqualToIgnoringCase(wallet);
        assertThat(status.providerNetworkStatus()).isEqualTo("ACTIVE");
        assertThat(status.fullyOperational()).isTrue();
    }

    @Test
    void shouldExposeDivergenceWithoutClaimingOperationalStatus() {
        String wallet = "0x00000000000000000000000000000000000000aa";
        when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(wallet);
        when(walletService.isLabProvider(wallet)).thenReturn(true);
        when(walletService.isInstitution(wallet)).thenReturn(false);
        when(walletService.resolveInstitutionWalletForOrganization("uni.example"))
            .thenReturn("0x00000000000000000000000000000000000000bb");
        when(walletService.getOrganizationBackendUrl("uni.example")).thenReturn("https://old.example");
        when(walletService.getAuthorizedInstitutionalBackend(wallet)).thenReturn(wallet);
        when(walletService.getProviderNetworkStatus(wallet)).thenReturn(2);

        InstitutionOnChainStatusService.Status status =
            new InstitutionOnChainStatusService(walletService, institutionalWalletService)
                .inspect("uni.example", "https://gateway.uni.example", true);

        assertThat(status.onChainStatusAvailable()).isTrue();
        assertThat(status.providerNetworkStatus()).isEqualTo("SUSPENDED");
        assertThat(status.fullyOperational()).isFalse();
    }
}
