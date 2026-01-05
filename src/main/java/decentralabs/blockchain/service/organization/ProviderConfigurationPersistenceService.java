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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Service to persist provider configuration to file
 */
@Service
@Slf4j
public class ProviderConfigurationPersistenceService {

    private static final String CONFIG_FILE = "config/provider.properties";

    @Value("${spring.config.location:}")
    private String configLocation;

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
            payload.getProviderOrganization(),
            payload.getPublicBaseUrl(),
            "token"
        );
    }

    /**
     * Save minimal configuration from consumer provisioning token (no provider fields)
     */
    public void saveConfigurationFromConsumerToken(ConsumerProvisioningTokenPayload payload) throws IOException {
        Properties properties = new Properties();

        // Load existing properties if file exists
        Path configPath = getConfigFilePath();
        if (Files.exists(configPath)) {
            try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
                properties.load(fis);
            }
        } else {
            // Create directory if it doesn't exist
            Path parentDir = configPath.getParent();
            if (parentDir != null) {
                Files.createDirectories(parentDir);
            }
        }

        // Consumer-only configuration (no publicBaseUrl, no provider fields)
        properties.setProperty("marketplace.base-url", payload.getMarketplaceBaseUrl());
        properties.setProperty("consumer.name", payload.getConsumerName());
        // Consumer-only flow reuses provider.organization to persist schacHomeOrganization used on-chain.
        properties.setProperty("provider.organization", payload.getConsumerOrganization());
        properties.setProperty("provisioning.source", "consumer-token");

        // Save to file
        try (FileOutputStream fos = new FileOutputStream(configPath.toFile())) {
            properties.store(fos, "Consumer Configuration - Auto-saved by DecentraLabs Blockchain Services");
        }

        log.info("Consumer configuration saved to {}", configPath);
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
        Properties properties = new Properties();

        // Load existing properties if file exists
        Path configPath = getConfigFilePath();
        if (Files.exists(configPath)) {
            try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
                properties.load(fis);
            }
        } else {
            // Create directory if it doesn't exist
            Path parentDir = configPath.getParent();
            if (parentDir != null) {
                Files.createDirectories(parentDir);
            }
        }

        // Update properties
        properties.setProperty("marketplace.base-url", marketplaceBaseUrl);
        properties.setProperty("provider.name", providerName);
        properties.setProperty("provider.email", providerEmail);
        properties.setProperty("provider.country", providerCountry);
        properties.setProperty("provider.organization", providerOrganization);
        properties.setProperty("public.base-url", publicBaseUrl);
        properties.setProperty("provisioning.source", source);

        // Save to file
        try (FileOutputStream fos = new FileOutputStream(configPath.toFile())) {
            properties.store(fos, "Provider Configuration - Auto-saved by DecentraLabs Blockchain Services");
        }

        log.info("Provider configuration saved to {}", configPath);
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
        Properties properties = new Properties();
        Path configPath = getConfigFilePath();

        if (Files.exists(configPath)) {
            try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
                properties.load(fis);
            }
        }

        return properties;
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
}
