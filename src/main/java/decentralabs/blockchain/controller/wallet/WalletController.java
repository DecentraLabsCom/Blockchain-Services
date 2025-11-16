package decentralabs.blockchain.controller.wallet;

import decentralabs.blockchain.util.EthereumAddressValidator;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import decentralabs.blockchain.dto.wallet.*;
import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;

@RestController
@RequestMapping("/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletService walletService;
    private final RateLimitService rateLimitService;
    private final InstitutionalWalletService institutionalWalletService;

    /**
     * POST /wallet/create
     * Creates a new Ethereum wallet with randomly generated private key
     */
    @PostMapping("/create")
    public ResponseEntity<WalletResponse> createWallet(@Valid @RequestBody WalletCreateRequest request) {
        try {
            WalletResponse response = walletService.createWallet(request.getPassword());
            
            // Auto-configure as institutional wallet
            if (response.isSuccess() && response.getAddress() != null) {
                institutionalWalletService.saveConfigToFile(response.getAddress(), request.getPassword());
                // Reinitialize to load the new config
                institutionalWalletService.initializeInstitutionalWallet();
            }
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(WalletResponse.error("Error creating wallet: " + e.getMessage()));
        }
    }

    /**
     * POST /wallet/import
     * Imports a wallet from private key or mnemonic
     */
    @PostMapping("/import")
    public ResponseEntity<WalletResponse> importWallet(@Valid @RequestBody WalletImportRequest request) {
        try {
            WalletResponse response = walletService.importWallet(request);
            
            // Auto-configure as institutional wallet
            if (response.isSuccess() && response.getAddress() != null) {
                institutionalWalletService.saveConfigToFile(response.getAddress(), request.getPassword());
                // Reinitialize to load the new config
                institutionalWalletService.initializeInstitutionalWallet();
            }
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(WalletResponse.error("Error importing wallet: " + e.getMessage()));
        }
    }

    /**
     * POST /wallet/reveal
     * Reveals the institutional wallet private key (localhost-only access)
     */
    @PostMapping("/reveal")
    public ResponseEntity<WalletResponse> revealPrivateKey(@Valid @RequestBody WalletRevealRequest request) {
        WalletResponse response = walletService.revealInstitutionalPrivateKey(request.getPassword());
        HttpStatus status = response.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(response);
    }

    /**
     * GET /wallet/{address}/balance
     * Gets the balance of an Ethereum address
     */
    @GetMapping("/{address}/balance")
    public ResponseEntity<BalanceResponse> getBalance(@PathVariable String address) {
        // Validate Ethereum address format
        if (!EthereumAddressValidator.isValidAddress(address)) {
            return ResponseEntity.badRequest()
                .body(BalanceResponse.error("Invalid Ethereum address format"));
        }
        
        // Rate limiting check
        if (!rateLimitService.allowBalanceCheck(address)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(BalanceResponse.error("Rate limit exceeded. Too many balance checks."));
        }
        
        try {
            BalanceResponse response = walletService.getBalance(address);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(BalanceResponse.error("Error getting balance: " + e.getMessage()));
        }
    }

    /**
     * GET /wallet/{address}/transactions
     * Gets the transaction history of an address
     */
    @GetMapping("/{address}/transactions")
    public ResponseEntity<TransactionHistoryResponse> getTransactionHistory(@PathVariable String address) {
        try {
            TransactionHistoryResponse response = walletService.getTransactionHistory(address);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(TransactionHistoryResponse.error("Error getting transaction history: " + e.getMessage()));
        }
    }

    /**
     * GET /wallet/listen-events
     * Gets the status of configured contract event listeners
     */
    @GetMapping("/listen-events")
    public ResponseEntity<EventListenerResponse> getEventListenerStatus() {
        try {
            EventListenerResponse response = walletService.getEventListenerStatus();
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(EventListenerResponse.error("Error getting event listener status: " + e.getMessage()));
        }
    }

    /**
     * GET /wallet/networks
     * Lists available networks (mainnet, testnets)
     */
    @GetMapping("/networks")
    public ResponseEntity<NetworkResponse> getAvailableNetworks() {
        try {
            NetworkResponse response = walletService.getAvailableNetworks();
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(NetworkResponse.error("Error getting networks: " + e.getMessage()));
        }
    }

    /**
     * POST /wallet/switch-network
     * Switches the active network for operations
     */
    @PostMapping("/switch-network")
    public ResponseEntity<NetworkResponse> switchNetwork(@RequestBody NetworkSwitchRequest request) {
        try {
            NetworkResponse response = walletService.switchNetwork(request.getNetworkId());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(NetworkResponse.error("Error switching network: " + e.getMessage()));
        }
    }

}
