package decentralabs.blockchain.controller.wallet;

import decentralabs.blockchain.dto.wallet.BalanceResponse;
import decentralabs.blockchain.dto.wallet.EventListenerResponse;
import decentralabs.blockchain.dto.wallet.NetworkResponse;
import decentralabs.blockchain.dto.wallet.NetworkSwitchRequest;
import decentralabs.blockchain.dto.wallet.TransactionHistoryResponse;
import decentralabs.blockchain.dto.wallet.WalletCreateRequest;
import decentralabs.blockchain.dto.wallet.WalletImportRequest;
import decentralabs.blockchain.dto.wallet.WalletResponse;
import decentralabs.blockchain.dto.wallet.WalletRevealRequest;
import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.wallet.WalletAdministrationService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/wallet")
@RequiredArgsConstructor
public class WalletController {

    private final WalletAdministrationService walletAdministrationService;
    private final WalletService walletService;
    private final RateLimitService rateLimitService;

    @PostMapping("/create")
    public ResponseEntity<WalletResponse> createWallet(@Valid @RequestBody WalletCreateRequest request) {
        try {
            WalletResponse response =
                walletAdministrationService.createAndConfigureInstitutionalWallet(request.getPassword());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(WalletResponse.error("Error creating wallet: " + e.getMessage()));
        }
    }

    @PostMapping("/import")
    public ResponseEntity<WalletResponse> importWallet(@Valid @RequestBody WalletImportRequest request) {
        try {
            WalletResponse response = walletAdministrationService.importAndConfigureInstitutionalWallet(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(WalletResponse.error("Error importing wallet: " + e.getMessage()));
        }
    }

    @PostMapping("/reveal")
    public ResponseEntity<WalletResponse> revealPrivateKey(@Valid @RequestBody WalletRevealRequest request) {
        WalletResponse response = walletService.revealInstitutionalPrivateKey(request.getPassword());
        HttpStatus status = response.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(response);
    }

    @GetMapping("/{address}/balance")
    public ResponseEntity<BalanceResponse> getBalance(
        @PathVariable String address,
        @RequestParam(required = false) String network
    ) {
        if (!EthereumAddressValidator.isValidAddress(address)) {
            return ResponseEntity.badRequest()
                .body(BalanceResponse.error("Invalid Ethereum address format"));
        }
        if (!rateLimitService.allowBalanceCheck(address)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .body(BalanceResponse.error("Rate limit exceeded. Too many balance checks."));
        }
        try {
            BalanceResponse response = walletService.getBalance(address, network);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(BalanceResponse.error("Error getting balance: " + e.getMessage()));
        }
    }

    @GetMapping("/{address}/transactions")
    public ResponseEntity<TransactionHistoryResponse> getTransactionHistory(
        @PathVariable String address,
        @RequestParam(required = false) String network
    ) {
        try {
            TransactionHistoryResponse response = walletService.getTransactionHistory(address, network);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(TransactionHistoryResponse.error("Error getting transaction history: " + e.getMessage()));
        }
    }

    @GetMapping("/listen-events")
    public ResponseEntity<EventListenerResponse> getEventListenerStatus(
        @RequestParam(required = false) String network
    ) {
        try {
            EventListenerResponse response = walletService.getEventListenerStatus(network);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(EventListenerResponse.error("Error getting event listener status: " + e.getMessage()));
        }
    }

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
