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
        // Forward /wallet-dashboard to /wallet-dashboard/index.html (with or without trailing slash)
        registry.addViewController("/wallet-dashboard")
                .setViewName("forward:/wallet-dashboard/index.html");
        registry.addViewController("/wallet-dashboard/")
                .setViewName("forward:/wallet-dashboard/index.html");
    }
}
