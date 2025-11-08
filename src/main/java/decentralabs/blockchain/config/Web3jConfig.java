package decentralabs.blockchain.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.web3j.protocol.Web3j;

import decentralabs.blockchain.service.wallet.WalletService;

/**
 * Configuration class for Web3j bean
 */
@Configuration
public class Web3jConfig {

    @Autowired
    private WalletService walletService;

    @Bean
    public Web3j web3j() {
        return walletService.getWeb3jInstance();
    }
}
