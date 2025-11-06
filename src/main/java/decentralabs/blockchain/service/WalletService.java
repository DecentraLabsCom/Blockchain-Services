package decentralabs.blockchain.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.dto.*;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class WalletService {

    @Value("${rpc.url}")
    private String defaultRpcUrl;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${wallet.address}")
    private String defaultWalletAddress;

    @Value("${base.domain}")
    private String baseDomain;

    // Optional network-specific RPC configurations (with default values)
    @Value("${ethereum.mainnet.rpc.url:https://mainnet.infura.io/v3/YOUR_PROJECT_ID}")
    private String mainnetRpcUrl;

    @Value("${ethereum.sepolia.rpc.url:https://sepolia.infura.io/v3/YOUR_PROJECT_ID}")
    private String sepoliaRpcUrl;

    @Value("${ethereum.goerli.rpc.url:https://goerli.infura.io/v3/YOUR_PROJECT_ID}")
    private String goerliRpcUrl;

    // Cache of Web3j connections per network
    private final Map<String, Web3j> web3jInstances = new ConcurrentHashMap<>();
    private String activeNetwork;

    @PostConstruct
    public void init() {
        // Use sepolia by default since rpc.url points to sepolia
        this.activeNetwork = "sepolia";
        log.info("WalletService initialized with active network: {} using RPC: {}", activeNetwork, defaultRpcUrl);
    }

    // Cache of encrypted wallets (use Redis/database in production)
    private final Map<String, String> encryptedWallets = new ConcurrentHashMap<>();

    /**
     * Creates a new Ethereum wallet
     */
    public WalletResponse createWallet(String password) {
        try {
            // Generate random private key
            ECKeyPair keyPair = Keys.createEcKeyPair();
            String privateKey = Numeric.toHexStringWithPrefix(keyPair.getPrivateKey());
            String address = Keys.getAddress(keyPair.getPublicKey());

            // Encrypt the private key
            String encryptedPrivateKey = encryptPrivateKey(privateKey, password);

            // Save to cache (use database in production)
            encryptedWallets.put(address, encryptedPrivateKey);

            log.info("Created new wallet: {}", address);

            return WalletResponse.builder()
                .success(true)
                .address(address)
                .encryptedPrivateKey(encryptedPrivateKey)
                .message("Wallet created successfully")
                .build();

        } catch (Exception e) {
            log.error("Error creating wallet", e);
            return WalletResponse.error("Failed to create wallet: " + e.getMessage());
        }
    }

    /**
     * Imports a wallet from private key or mnemonic
     */
    public WalletResponse importWallet(WalletImportRequest request) {
        try {
            String address;
            String encryptedPrivateKey;

            if (request.getPrivateKey() != null) {
                // Import from private key
                ECKeyPair keyPair = ECKeyPair.create(Numeric.toBigInt(request.getPrivateKey()));
                address = Keys.getAddress(keyPair.getPublicKey());
                encryptedPrivateKey = encryptPrivateKey(request.getPrivateKey(), request.getPassword());
            } else if (request.getMnemonic() != null) {
                // Import from mnemonic (BIP39)
                Credentials credentials = WalletUtils.loadBip39Credentials(
                    request.getPassword(), request.getMnemonic());
                address = credentials.getAddress();
                encryptedPrivateKey = encryptPrivateKey(
                    Numeric.toHexStringWithPrefix(credentials.getEcKeyPair().getPrivateKey()),
                    request.getPassword());
            } else {
                return WalletResponse.error("Either privateKey or mnemonic must be provided");
            }

            // Save to cache
            encryptedWallets.put(address, encryptedPrivateKey);

            log.info("Imported wallet: {}", address);

            return WalletResponse.builder()
                .success(true)
                .address(address)
                .encryptedPrivateKey(encryptedPrivateKey)
                .message("Wallet imported successfully")
                .build();

        } catch (Exception e) {
            log.error("Error importing wallet", e);
            return WalletResponse.error("Failed to import wallet: " + e.getMessage());
        }
    }

    /**
     * Gets the balance of an address
     */
    public BalanceResponse getBalance(String address) {
        try {
            Web3j web3j = getWeb3jInstance();
            EthGetBalance balance = web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).send();

            BigDecimal ethBalance = Convert.fromWei(balance.getBalance().toString(), Convert.Unit.ETHER);

            return BalanceResponse.builder()
                .success(true)
                .address(address)
                .balanceWei(balance.getBalance().toString())
                .balanceEth(ethBalance.toString())
                .network(activeNetwork)
                .build();

        } catch (Exception e) {
            log.error("Error getting balance for address: {}", address, e);
            return BalanceResponse.error("Failed to get balance: " + e.getMessage());
        }
    }

    /**
     * Signs a message with the wallet
     */
    public SignMessageResponse signMessage(SignMessageRequest request) {
        try {
            // Decrypt the private key
            String privateKey = decryptPrivateKey(request.getEncryptedPrivateKey(), request.getPassword());
            Credentials credentials = Credentials.create(privateKey);

            // Sign the message
            Sign.SignatureData signature = Sign.signPrefixedMessage(
                request.getMessage().getBytes(), credentials.getEcKeyPair());

            // Convert signature to hex format
            String signatureHex = Numeric.toHexString(signature.getR()) +
                                Numeric.toHexString(signature.getS()).substring(2) +
                                Numeric.toHexString(signature.getV()).substring(2);

            return SignMessageResponse.builder()
                .success(true)
                .address(credentials.getAddress())
                .message(request.getMessage())
                .signature(signatureHex)
                .build();

        } catch (Exception e) {
            log.error("Error signing message", e);
            return SignMessageResponse.error("Failed to sign message: " + e.getMessage());
        }
    }

    /**
     * Signs a transaction
     */
    public SignTransactionResponse signTransaction(SignTransactionRequest request) {
        try {
            // Descifrar la clave privada
            String privateKey = decryptPrivateKey(request.getEncryptedPrivateKey(), request.getPassword());
            Credentials credentials = Credentials.create(privateKey);

            Web3j web3j = getWeb3jInstance();

            // Create the transaction
            BigInteger gasPrice = request.getGasPrice() != null ?
                new BigInteger(request.getGasPrice()) :
                web3j.ethGasPrice().send().getGasPrice();

            BigInteger gasLimit = request.getGasLimit() != null ?
                new BigInteger(request.getGasLimit()) :
                BigInteger.valueOf(21000); // Default for transfers

            RawTransaction rawTransaction = RawTransaction.createEtherTransaction(
                request.getNonce() != null ? new BigInteger(request.getNonce()) : getNonce(credentials.getAddress()),
                gasPrice,
                gasLimit,
                request.getTo(),
                Convert.toWei(request.getValue(), Convert.Unit.ETHER).toBigInteger()
            );

            // Sign the transaction
            byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
            String signedTransactionHex = Numeric.toHexString(signedMessage);

            return SignTransactionResponse.builder()
                .success(true)
                .from(credentials.getAddress())
                .to(request.getTo())
                .value(request.getValue())
                .signedTransaction(signedTransactionHex)
                .build();

        } catch (Exception e) {
            log.error("Error signing transaction", e);
            return SignTransactionResponse.error("Failed to sign transaction: " + e.getMessage());
        }
    }

    /**
     * Sends a signed transaction
     */
    public SendTransactionResponse sendTransaction(SendTransactionRequest request) {
        try {
            Web3j web3j = getWeb3jInstance();

            // Send the transaction
            EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(request.getSignedTransaction()).send();

            if (ethSendTransaction.hasError()) {
                return SendTransactionResponse.error("Transaction failed: " + ethSendTransaction.getError().getMessage());
            }

            String transactionHash = ethSendTransaction.getTransactionHash();

            return SendTransactionResponse.builder()
                .success(true)
                .transactionHash(transactionHash)
                .network(activeNetwork)
                .build();

        } catch (Exception e) {
            log.error("Error sending transaction", e);
            return SendTransactionResponse.error("Failed to send transaction: " + e.getMessage());
        }
    }

    /**
     * Gets the transaction history (simplified)
     */
    public TransactionHistoryResponse getTransactionHistory(String address) {
        try {
            Web3j web3j = getWeb3jInstance();

            // Get the number of sent transactions
            EthGetTransactionCount txCount = web3j.ethGetTransactionCount(address, DefaultBlockParameterName.LATEST).send();

            List<TransactionInfo> transactions = new ArrayList<>();
            // In a real implementation, we would query an indexer like Etherscan API
            // or use contract events for related transactions

            return TransactionHistoryResponse.builder()
                .success(true)
                .address(address)
                .transactionCount(txCount.getTransactionCount().toString())
                .transactions(transactions)
                .network(activeNetwork)
                .build();

        } catch (Exception e) {
            log.error("Error getting transaction history for address: {}", address, e);
            return TransactionHistoryResponse.error("Failed to get transaction history: " + e.getMessage());
        }
    }

    /**
     * Gets the status of configured contract event listeners
     */
    public EventListenerResponse getEventListenerStatus() {
        try {
            return EventListenerResponse.builder()
                .success(true)
                .contractAddress(contractAddress)
                .network(activeNetwork)
                .message("Event listeners are configured automatically on startup from application.properties")
                .build();

        } catch (Exception e) {
            log.error("Error getting event listener status", e);
            return EventListenerResponse.error("Failed to get event listener status: " + e.getMessage());
        }
    }

    /**
     * Lists available networks
     */
    public NetworkResponse getAvailableNetworks() {
        List<NetworkInfo> networks = Arrays.asList(
            new NetworkInfo("mainnet", "Ethereum Mainnet", mainnetRpcUrl, 1),
            new NetworkInfo("sepolia", "Sepolia Testnet", sepoliaRpcUrl, 11155111),
            new NetworkInfo("goerli", "Goerli Testnet", goerliRpcUrl, 5)
        );

        return NetworkResponse.builder()
            .success(true)
            .networks(networks)
            .activeNetwork(activeNetwork)
            .build();
    }

    /**
     * Switches the active network
     */
    public NetworkResponse switchNetwork(String networkId) {
        if (!Arrays.asList("mainnet", "sepolia", "goerli").contains(networkId)) {
            return NetworkResponse.error("Invalid network: " + networkId);
        }

        activeNetwork = networkId;
        log.info("Switched to network: {}", networkId);

        return getAvailableNetworks();
    }

    // Helper methods

    public Web3j getWeb3jInstance() {
        return web3jInstances.computeIfAbsent(activeNetwork, this::createWeb3jInstance);
    }

    private Web3j createWeb3jInstance(String network) {
        String rpcUrl = switch (network) {
            case "mainnet" -> mainnetRpcUrl; // Use specific configuration if available
            case "sepolia" -> sepoliaRpcUrl; // Use specific configuration if available
            case "goerli" -> goerliRpcUrl;   // Use specific configuration if available
            default -> defaultRpcUrl;        // Fallback to existing rpc.url
        };

        return Web3j.build(new HttpService(rpcUrl));
    }

    private BigInteger getNonce(String address) throws Exception {
        Web3j web3j = getWeb3jInstance();
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
            address, DefaultBlockParameterName.PENDING).send();
        return ethGetTransactionCount.getTransactionCount();
    }

    private String encryptPrivateKey(String privateKey, String password) {
        // In production, use a strong encryption algorithm like AES
        // This is a simplified implementation
        return Base64.getEncoder().encodeToString((privateKey + ":" + password).getBytes());
    }

    private String decryptPrivateKey(String encryptedPrivateKey, String password) {
        // In production, use a strong encryption algorithm like AES
        // This is a simplified implementation
        String decoded = new String(Base64.getDecoder().decode(encryptedPrivateKey));
        String[] parts = decoded.split(":");
        if (parts.length != 2 || !parts[1].equals(password)) {
            throw new IllegalArgumentException("Invalid password or corrupted wallet");
        }
        return parts[0];
    }
}