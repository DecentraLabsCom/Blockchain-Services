package decentralabs.blockchain.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import decentralabs.blockchain.service.wallet.WalletService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;
import org.web3j.protocol.Web3j;

class Web3jConfigTest {

    @Test
    void web3j_returnsInstanceFromWalletService() {
        Web3jConfig config = new Web3jConfig();
        WalletService walletService = Mockito.mock(WalletService.class);
        Web3j web3j = Mockito.mock(Web3j.class);
        ReflectionTestUtils.setField(config, "walletService", walletService);
        when(walletService.getWeb3jInstance()).thenReturn(web3j);

        Web3j result = config.web3j();

        assertThat(result).isSameAs(web3j);
        verify(walletService).getWeb3jInstance();
    }
}
