package decentralabs.blockchain.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import jakarta.annotation.Nonnull;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC Configuration
 * Configures view controllers and static resource handling
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * RestTemplate bean for HTTP client operations
     * Used by InstitutionRegistrationService to communicate with marketplace
     */
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    // Provide a default ObjectMapper and a lightweight JSON HttpMessageConverter for test contexts
    // Only created when no other ObjectMapper/Converter bean is present to avoid interfering with auto-configuration
    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
    public ObjectMapper objectMapper() {
        // Register Java time and other standard modules when available.
        return JsonMapper.builder()
            .findAndAddModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .build();
    }

    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
    public JacksonHttpMessageConverter jacksonHttpMessageConverter(ObjectMapper om) {
        return new JacksonHttpMessageConverter(om);
    }

    @Override
    public void addViewControllers(@Nonnull ViewControllerRegistry registry) {
        // Default root to the wallet dashboard UI in standalone mode.
        registry.addViewController("/")
                .setViewName("redirect:/wallet-dashboard/");
        // Redirect to include trailing slash so relative assets resolve correctly.
        registry.addViewController("/wallet-dashboard")
                .setViewName("redirect:/wallet-dashboard/");
        // Forward /wallet-dashboard/ to /wallet-dashboard/index.html
        registry.addViewController("/wallet-dashboard/")
                .setViewName("forward:/wallet-dashboard/index.html");
        // Redirect /institution-config to include trailing slash
        registry.addViewController("/institution-config")
                .setViewName("redirect:/institution-config/");
        // Forward /institution-config/ to static HTML
        registry.addViewController("/institution-config/")
                .setViewName("forward:/institution-config/index.html");
    }
}
