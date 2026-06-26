package decentralabs.blockchain.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.web3j.protocol.Web3j;

import decentralabs.blockchain.service.wallet.WalletService;

/**
 * Configuration class for Web3j bean
 */
@Configuration
public class Web3jConfig {

    private final WalletService walletService;

    public Web3jConfig(WalletService walletService) {
        this.walletService = walletService;
    }

    @Bean
    public Web3j web3j() {
        return walletService.getWeb3jInstance();
    }
}
