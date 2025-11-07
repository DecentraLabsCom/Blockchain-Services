package decentralabs.blockchain.controller.wallet;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import decentralabs.blockchain.dto.*;
import decentralabs.blockchain.service.InstitutionalReservationService;
import decentralabs.blockchain.service.WalletService;

@RestController
@RequestMapping("/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletService walletService;
    private final InstitutionalReservationService institutionalReservationService;

    /**
     * POST /wallet/create
     * Creates a new Ethereum wallet with randomly generated private key
     */
    @PostMapping("/create")
    public ResponseEntity<WalletResponse> createWallet(@RequestBody WalletCreateRequest request) {
        try {
            WalletResponse response = walletService.createWallet(request.getPassword());
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
    public ResponseEntity<WalletResponse> importWallet(@RequestBody WalletImportRequest request) {
        try {
            WalletResponse response = walletService.importWallet(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(WalletResponse.error("Error importing wallet: " + e.getMessage()));
        }
    }

    /**
     * GET /wallet/{address}/balance
     * Gets the balance of an Ethereum address
     */
    @GetMapping("/{address}/balance")
    public ResponseEntity<BalanceResponse> getBalance(@PathVariable String address) {
        try {
            BalanceResponse response = walletService.getBalance(address);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(BalanceResponse.error("Error getting balance: " + e.getMessage()));
        }
    }

    /**
     * POST /wallet/sign-message
     * Signs a message with the wallet's private key
     */
    @PostMapping("/sign-message")
    public ResponseEntity<SignMessageResponse> signMessage(@RequestBody SignMessageRequest request) {
        try {
            SignMessageResponse response = walletService.signMessage(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(SignMessageResponse.error("Error signing message: " + e.getMessage()));
        }
    }

    /**
     * POST /wallet/sign-transaction
     * Signs an Ethereum transaction
     */
    @PostMapping("/sign-transaction")
    public ResponseEntity<SignTransactionResponse> signTransaction(@RequestBody SignTransactionRequest request) {
        try {
            SignTransactionResponse response = walletService.signTransaction(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(SignTransactionResponse.error("Error signing transaction: " + e.getMessage()));
        }
    }

    /**
     * POST /wallet/send-transaction
     * Sends a signed transaction to the network
     */
    @PostMapping("/send-transaction")
    public ResponseEntity<SendTransactionResponse> sendTransaction(@RequestBody SendTransactionRequest request) {
        try {
            SendTransactionResponse response = walletService.sendTransaction(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(SendTransactionResponse.error("Error sending transaction: " + e.getMessage()));
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

    /**
     * POST /wallet/institutional-reservation
     * Processes an institutional reservation request
     */
    @PostMapping("/institutional-reservation")
    public ResponseEntity<?> createInstitutionalReservation(@RequestBody InstitutionalReservationRequest request) {
        try {
            return ResponseEntity.ok(institutionalReservationService.processReservation(request));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(java.util.Map.of("success", false, "error", e.getMessage()));
        }
    }
}
