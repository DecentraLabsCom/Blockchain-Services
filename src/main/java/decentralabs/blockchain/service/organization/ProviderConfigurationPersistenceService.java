package decentralabs.blockchain.service.organization;

import decentralabs.blockchain.dto.provider.ConsumerProvisioningTokenPayload;
import decentralabs.blockchain.dto.provider.ProviderConfigurationRequest;
import decentralabs.blockchain.dto.provider.ProvisioningTokenPayload;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Properties;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Service to persist provider configuration to file
 */
@Service
@Slf4j
public class ProviderConfigurationPersistenceService {

    private static final String CONFIG_FILE = "config/provider.properties";
    private static final String REGISTERED_CONTRACT_SUFFIX = ".contract.address";

    @Value("${provider.config.path:}")
    private String configLocation;

    @Value("${contract.address}")
    private String currentContractAddress;

    /**
     * Serializes read/modify/replace cycles inside this backend instance. The
     * temporary-file + rename commit below also guarantees readers never see a
     * partially written provider.properties file.
     */
    private final ReentrantLock persistenceLock = new ReentrantLock();

    /**
     * Save provider configuration to persistent file
     */
    public void saveConfiguration(ProviderConfigurationRequest request) throws IOException {
        saveConfigurationInternal(
            request.getMarketplaceBaseUrl(),
            request.getProviderName(),
            request.getProviderEmail(),
            request.getProviderCountry(),
            request.getProviderOrganization(),
            request.getPublicBaseUrl(),
            "manual"
        );
    }

    /**
     * Save configuration coming from provisioning token
     */
    public void saveConfigurationFromToken(ProvisioningTokenPayload payload) throws IOException {
        saveConfigurationInternal(
            payload.getMarketplaceBaseUrl(),
            payload.getProviderName(),
            payload.getProviderEmail(),
            payload.getProviderCountry(),
            payload.getInstitutionId(),
            payload.getCanonicalBackendOrigin(),
            "token"
        );
    }

    /**
     * Persists the provider configuration and its on-chain registration marker
     * as one local snapshot. The remote chain transaction is completed by the
     * caller before this method is invoked; retries are therefore safe because
     * the operation is an idempotent replacement of the same file.
     */
    public void persistProviderRegistration(ProvisioningTokenPayload payload) throws IOException {
        persistenceLock.lock();
        try {
            Path configPath = getConfigFilePath();
            Properties properties = readPropertiesForUpdate(configPath);
            applyProviderConfiguration(
                properties,
                payload.getMarketplaceBaseUrl(),
                payload.getProviderName(),
                payload.getProviderEmail(),
                payload.getProviderCountry(),
                payload.getInstitutionId(),
                payload.getCanonicalBackendOrigin(),
                "token"
            );
            markAsRegistered(properties, InstitutionRole.PROVIDER);
            writePropertiesAtomically(
                configPath,
                properties,
                "Provider Configuration - Atomically committed after registration"
            );
            log.info("Provider registration configuration committed to {}", configPath);
        } finally {
            persistenceLock.unlock();
        }
    }

    /**
     * Save minimal configuration from consumer provisioning token (no provider fields)
     */
    public void saveConfigurationFromConsumerToken(ConsumerProvisioningTokenPayload payload) throws IOException {
        persistenceLock.lock();
        try {
            Path configPath = getConfigFilePath();
            Properties properties = readPropertiesForUpdate(configPath);
            applyConsumerConfiguration(properties, payload);
            writePropertiesAtomically(
                configPath,
                properties,
                "Consumer Configuration - Auto-saved by DecentraLabs Blockchain Services"
            );
            log.info("Consumer configuration saved to {}", configPath);
        } finally {
            persistenceLock.unlock();
        }
    }

    /**
     * Persists consumer configuration and its on-chain registration marker as
     * one local snapshot.
     */
    public void persistConsumerRegistration(ConsumerProvisioningTokenPayload payload) throws IOException {
        persistenceLock.lock();
        try {
            Path configPath = getConfigFilePath();
            Properties properties = readPropertiesForUpdate(configPath);
            applyConsumerConfiguration(properties, payload);
            markAsRegistered(properties, InstitutionRole.CONSUMER);
            writePropertiesAtomically(
                configPath,
                properties,
                "Consumer Configuration - Atomically committed after registration"
            );
            log.info("Consumer registration configuration committed to {}", configPath);
        } finally {
            persistenceLock.unlock();
        }
    }

    private void saveConfigurationInternal(
        String marketplaceBaseUrl,
        String providerName,
        String providerEmail,
        String providerCountry,
        String providerOrganization,
        String publicBaseUrl,
        String source
    ) throws IOException {
        persistenceLock.lock();
        try {
            Path configPath = getConfigFilePath();
            Properties properties = readPropertiesForUpdate(configPath);
            applyProviderConfiguration(
                properties,
                marketplaceBaseUrl,
                providerName,
                providerEmail,
                providerCountry,
                providerOrganization,
                publicBaseUrl,
                source
            );
            writePropertiesAtomically(
                configPath,
                properties,
                "Provider Configuration - Auto-saved by DecentraLabs Blockchain Services"
            );
            log.info("Provider configuration saved to {}", configPath);
        } finally {
            persistenceLock.unlock();
        }
    }

    /**
     * Mark institution as registered for a specific role
     *
     * @param role Institution role (PROVIDER or CONSUMER)
     * @throws IOException if unable to write to configuration file
     */
    public void markAsRegistered(InstitutionRole role) throws IOException {
        persistenceLock.lock();
        try {
            Path configPath = getConfigFilePath();
            Properties properties = readPropertiesForUpdate(configPath);
            markAsRegistered(properties, role);
            writePropertiesAtomically(
                configPath,
                properties,
                "Institution Configuration - Auto-saved by DecentraLabs Blockchain Services"
            );
            log.info("{} marked as registered in configuration", role);
        } finally {
            persistenceLock.unlock();
        }
    }

    private Properties readPropertiesForUpdate(Path configPath) throws IOException {
        Properties properties = new Properties();
        if (Files.exists(configPath)) {
            try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
                properties.load(fis);
            }
        } else {
            Path parentDir = configPath.toAbsolutePath().getParent();
            if (parentDir != null) {
                Files.createDirectories(parentDir);
            }
        }
        return properties;
    }

    private void applyProviderConfiguration(
        Properties properties,
        String marketplaceBaseUrl,
        String providerName,
        String providerEmail,
        String providerCountry,
        String providerOrganization,
        String publicBaseUrl,
        String source
    ) {
        properties.setProperty("marketplace.base-url", marketplaceBaseUrl);
        properties.setProperty("provider.name", providerName);
        properties.setProperty("provider.email", providerEmail);
        properties.setProperty("provider.country", providerCountry);
        properties.setProperty("provider.organization", providerOrganization);
        properties.setProperty("public.base-url", publicBaseUrl);
        properties.setProperty("provisioning.source", source);
    }

    private void applyConsumerConfiguration(
        Properties properties,
        ConsumerProvisioningTokenPayload payload
    ) {
        properties.setProperty("marketplace.base-url", payload.getMarketplaceBaseUrl());
        properties.setProperty("consumer.name", payload.getConsumerName());
        // Consumer-only flow reuses provider.organization to persist schacHomeOrganization used on-chain.
        properties.setProperty("provider.organization", payload.getInstitutionId());
        properties.setProperty("public.base-url", payload.getCanonicalBackendOrigin());
        properties.setProperty("provisioning.source", "consumer-token");
    }

    private void markAsRegistered(Properties properties, InstitutionRole role) {
        properties.setProperty(role.getRegisteredFlag(), "true");
        if (currentContractAddress != null && !currentContractAddress.isBlank()) {
            properties.setProperty(
                role.getRegisteredFlag() + REGISTERED_CONTRACT_SUFFIX,
                currentContractAddress.trim()
            );
        }
    }

    /**
     * Writes a complete properties snapshot beside the target and commits it
     * with a same-directory rename. A reader therefore observes either the old
     * snapshot or the new one, never a truncated file.
     */
    private void writePropertiesAtomically(Path configPath, Properties properties, String comment) throws IOException {
        Path target = configPath.toAbsolutePath();
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Path temporary = Files.createTempFile(
            parent,
            target.getFileName().toString() + ".",
            ".tmp"
        );
        boolean committed = false;
        try {
            try (FileOutputStream fos = new FileOutputStream(temporary.toFile());
                 FileChannel channel = fos.getChannel()) {
                // This file contains deployment metadata (not credentials or tokens)
                // and is the persisted format consumed by the configuration UI.
                // codeql[java/cleartext-storage-in-properties]
                properties.store(fos, comment);
                fos.flush();
                channel.force(true);
            }

            try {
                Files.move(
                    temporary,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
                );
            } catch (AtomicMoveNotSupportedException | FileAlreadyExistsException unsupported) {
                // The fallback still replaces only after the complete temporary
                // snapshot has been closed and flushed.
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            committed = true;
        } finally {
            if (!committed) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    /**
     * Get the path to the configuration file
     */
    private Path getConfigFilePath() {
        if (configLocation != null && !configLocation.isBlank()) {
            // Use custom config location if specified
            Path customPath = Paths.get(configLocation);
            if (Files.isDirectory(customPath)) {
                return customPath.resolve("provider.properties");
            }
            return customPath;
        }

        // Default to config/provider.properties in application directory
        return Paths.get(CONFIG_FILE);
    }

    /**
     * Check if configuration file exists
     */
    public boolean configurationFileExists() {
        return Files.exists(getConfigFilePath());
    }

    /**
     * Load configuration from file
     */
    public Properties loadConfiguration() throws IOException {
        persistenceLock.lock();
        try {
            Properties properties = new Properties();
            Path configPath = getConfigFilePath();

            if (Files.exists(configPath)) {
                try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
                    properties.load(fis);
                }
                invalidateRegistrationFlagsForContractChange(properties, configPath);
            }

            return properties;
        } finally {
            persistenceLock.unlock();
        }
    }

    /**
     * Load configuration without throwing, returns empty properties on error
     */
    public Properties loadConfigurationSafe() {
        try {
            return loadConfiguration();
        } catch (IOException e) {
            log.warn("Unable to load provider configuration file: {}", e.getMessage());
            return new Properties();
        }
    }

    private void invalidateRegistrationFlagsForContractChange(Properties properties, Path configPath) throws IOException {
        String expectedContract = currentContractAddress == null ? "" : currentContractAddress.trim();
        if (expectedContract.isBlank()) {
            return;
        }

        boolean changed = false;
        for (InstitutionRole role : InstitutionRole.values()) {
            String registeredFlag = role.getRegisteredFlag();
            if (!"true".equalsIgnoreCase(properties.getProperty(registeredFlag, "false"))) {
                continue;
            }

            String storedContract = properties.getProperty(registeredFlag + REGISTERED_CONTRACT_SUFFIX, "").trim();
            if (!expectedContract.equalsIgnoreCase(storedContract)) {
                properties.setProperty(registeredFlag, "false");
                properties.setProperty(registeredFlag + REGISTERED_CONTRACT_SUFFIX, expectedContract);
                changed = true;
                log.info(
                    "Invalidated {} because contract.address changed (stored={}, current={})",
                    registeredFlag,
                    storedContract.isBlank() ? "<empty>" : storedContract,
                    expectedContract
                );
            }
        }

        if (changed) {
            writePropertiesAtomically(
                configPath,
                properties,
                "Institution Configuration - Auto-saved by DecentraLabs Blockchain Services"
            );
        }
    }
}
