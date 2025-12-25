package decentralabs.blockchain.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;

/**
 * Legacy stub (no-op). Modal flow handles configuration; filter is not registered as a bean.
 */
@Slf4j
public class ProviderConfigurationFilter implements Filter {

    @Value("${marketplace.base-url:}")
    private String marketplaceBaseUrl;

    @Value("${marketplace.api-key:}")
    private String marketplaceApiKey;

    @Value("${provider.name:}")
    private String providerName;

    @Value("${provider.email:}")
    private String providerEmail;

    @Value("${provider.country:}")
    private String providerCountry;

    @Value("${provider.organization:}")
    private String providerOrganization;

    @Value("${public.base-url:}")
    private String publicBaseUrl;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        chain.doFilter(request, response);
    }

    /**
     * Check if all required provider configuration is present
     */
    private boolean isProviderConfigured() {
        return !isBlank(marketplaceBaseUrl)
            && !isBlank(marketplaceApiKey)
            && !isBlank(providerName)
            && !isBlank(providerEmail)
            && !isBlank(providerCountry)
            && !isBlank(providerOrganization)
            && !isBlank(publicBaseUrl);
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
