package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.service.persistence.WalletPersistenceService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Credentials;

/**
 * Service for managing the institutional wallet used for automated transactions.
 * 
 * This service manages a SINGLE wallet that is used for:
 * - Automatic reservation confirmations/denials (event listeners)
 * - Institutional reservations (treasury operations)
 * - Administrative operations (treasury admin)
 * 
 * The institutional wallet is:
 * - Created once via POST /wallet/create with a password
 * - Stored encrypted in the persistence layer (/app/data/wallets.json)
 * - Loaded on service startup and cached in memory
 * - Decrypted only when needed to sign transactions
 * 
 * Security model:
 * - Private key: AES-256-GCM encrypted in /app/data/wallets.json (never in plain text)
 * - Password: Stored in environment variable (INSTITUTIONAL_WALLET_PASSWORD)
 * - Credentials: Cached in memory after first decryption (ephemeral)
 * - Access: Protected by localhost-only endpoints and CORS
 * 
 * Setup flow:
 * 1. Create wallet: POST /wallet/create {"password": "SecurePass123!"}
 * 2. Configure: INSTITUTIONAL_WALLET_ADDRESS=0x... INSTITUTIONAL_WALLET_PASSWORD=SecurePass123!
 * 3. Restart service: Service loads encrypted wallet from persistence
 * 4. Auto-sign: Service decrypts wallet when needed to sign transactions
 * 
 * @see WalletService for wallet creation and encryption
 * @see WalletPersistenceService for encrypted storage
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalWalletService {
    
    private final WalletService walletService;
    private final WalletPersistenceService persistenceService;
    
    /**
     * Address of the institutional wallet (configured in application.properties)
     * This wallet must be created first using POST /wallet/create
     */
    @Value("${institutional.wallet.address:}")
    private String institutionalWalletAddress;
    
    /**
     * Password to decrypt the institutional wallet's private key
     * SECURITY: Store this in AWS Secrets Manager, Azure Key Vault, or similar
     * Never commit this password to version control
     */
    @Value("${institutional.wallet.password:}")
    private String institutionalWalletPassword;
    
    /**
     * Cached credentials to avoid decrypting on every transaction
     * Only initialized when first needed (lazy loading)
     */
    private volatile Credentials cachedCredentials;
    
    /**
     * Validates that the institutional wallet exists in persistence on startup.
     * Does NOT decrypt the wallet yet (lazy initialization for better startup time).
     * 
     * @throws IllegalStateException if wallet address or password not configured
     * @throws IllegalStateException if wallet not found in persistence
     */
    @PostConstruct
    public void initializeInstitutionalWallet() {
        // Check if institutional wallet is configured
        if (institutionalWalletAddress == null || institutionalWalletAddress.isBlank()) {
            log.warn("Institutional wallet address not configured. " +
                    "Set institutional.wallet.address in application.properties. " +
                    "Automated transaction signing will not be available.");
            return;
        }
        
        if (institutionalWalletPassword == null || institutionalWalletPassword.isBlank()) {
            log.warn("Institutional wallet password not configured. " +
                    "Set institutional.wallet.password in application.properties. " +
                    "Automated transaction signing will not be available.");
            return;
        }
        
        // Verify wallet exists in persistence (but don't decrypt yet)
        String encryptedKey = persistenceService.getWallet(institutionalWalletAddress);
        
        if (encryptedKey == null) {
            throw new IllegalStateException(
                "Institutional wallet not found at address: " + institutionalWalletAddress + ". " +
                "Please create it first using POST /wallet/create with your institutional password, " +
                "then configure institutional.wallet.address and institutional.wallet.password."
            );
        }
        
        log.info("Institutional wallet verified in persistence: {}", institutionalWalletAddress);
        log.info("Institutional wallet ready for automated transaction signing");
    }
    
    /**
     * Gets the credentials for the institutional wallet, decrypting if necessary.
     * Uses double-checked locking for thread-safe lazy initialization.
     * Credentials are cached after first decryption to avoid repeated decryption overhead.
     * 
     * @return Credentials object that can sign transactions
     * @throws IllegalStateException if wallet not configured or not found
     * @throws RuntimeException if decryption fails (wrong password or corrupted data)
     */
    public Credentials getInstitutionalCredentials() {
        // Fast path: return cached credentials if available
        Credentials local = cachedCredentials;
        if (local != null) {
            return local;
        }
        
        // Slow path: decrypt and cache
        synchronized (this) {
            local = cachedCredentials;
            if (local != null) {
                return local;
            }
            
            // Validate configuration
            if (institutionalWalletAddress == null || institutionalWalletAddress.isBlank()) {
                throw new IllegalStateException(
                    "Institutional wallet address not configured. " +
                    "Set institutional.wallet.address in application.properties."
                );
            }
            
            if (institutionalWalletPassword == null || institutionalWalletPassword.isBlank()) {
                throw new IllegalStateException(
                    "Institutional wallet password not configured. " +
                    "Set institutional.wallet.password in application.properties."
                );
            }
            
            // Load encrypted wallet from persistence
            String encryptedKey = persistenceService.getWallet(institutionalWalletAddress);
            if (encryptedKey == null) {
                throw new IllegalStateException(
                    "Institutional wallet not found in persistence: " + institutionalWalletAddress + ". " +
                    "Create it with POST /wallet/create first."
                );
            }
            
            // Decrypt private key with password (throws RuntimeException if wrong password)
            String privateKey = walletService.decryptPrivateKey(
                encryptedKey, 
                institutionalWalletPassword
            );
            
            // Create credentials from decrypted private key
            local = Credentials.create(privateKey);
            
            // Clear private key from memory immediately (security best practice)
            privateKey = null;
            
            // Verify decrypted address matches configured address
            if (!local.getAddress().equalsIgnoreCase(institutionalWalletAddress)) {
                throw new IllegalStateException(
                    "Decrypted wallet address (" + local.getAddress() + ") " +
                    "does not match configured address (" + institutionalWalletAddress + "). " +
                    "Check your institutional.wallet.address and institutional.wallet.password configuration."
                );
            }
            
            cachedCredentials = local;
            log.info("Institutional wallet credentials initialized and cached for address: {}", 
                     local.getAddress());
            
            return local;
        }
    }
    
    /**
     * Clears the cached credentials, forcing re-decryption on next use.
     * Useful if the wallet password is rotated or credentials need to be refreshed.
     * 
     * This is a security-sensitive operation and should only be called when necessary.
     */
    public synchronized void clearCredentialsCache() {
        if (cachedCredentials != null) {
            log.info("Clearing institutional wallet credentials cache for address: {}", 
                     cachedCredentials.getAddress());
            cachedCredentials = null;
        }
    }
    
    /**
     * Checks if the institutional wallet is properly configured and available.
     * 
     * @return true if wallet address and password are configured, false otherwise
     */
    public boolean isConfigured() {
        return institutionalWalletAddress != null && !institutionalWalletAddress.isBlank()
            && institutionalWalletPassword != null && !institutionalWalletPassword.isBlank()
            && persistenceService.getWallet(institutionalWalletAddress) != null;
    }
    
    /**
     * Gets the configured institutional wallet address.
     * 
     * @return wallet address or null if not configured
     */
    public String getInstitutionalWalletAddress() {
        return institutionalWalletAddress;
    }
}
