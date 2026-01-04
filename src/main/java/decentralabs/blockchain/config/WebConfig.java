package decentralabs.blockchain.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC Configuration
 * Configures view controllers and static resource handling
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(@NonNull ViewControllerRegistry registry) {
        // Default root to the wallet dashboard UI in standalone mode.
        registry.addViewController("/")
                .setViewName("redirect:/wallet-dashboard/");
        // Redirect to include trailing slash so relative assets resolve correctly.
        registry.addViewController("/wallet-dashboard")
                .setViewName("redirect:/wallet-dashboard/");
        // Forward /wallet-dashboard/ to /wallet-dashboard/index.html
        registry.addViewController("/wallet-dashboard/")
                .setViewName("forward:/wallet-dashboard/index.html");
    }
}
