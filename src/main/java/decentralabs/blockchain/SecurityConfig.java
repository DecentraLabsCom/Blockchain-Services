package decentralabs.blockchain;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${allowed-origins}")
    private String[] allowedOrigins;

    @Value("${wallet.allowed-origins}")
    private String[] walletAllowedOrigins;
    
    @Value("${endpoint.wallet-auth}")
    private String walletAuthEndpoint;
    
    @Value("${endpoint.wallet-auth2}")
    private String walletAuth2Endpoint;
    
    @Value("${endpoint.jwks}")
    private String jwksEndpoint;
    
    @Value("${endpoint.message}")
    private String messageEndpoint;
    
    @Value("${endpoint.saml-auth}")
    private String samlAuthEndpoint;
    
    @Value("${endpoint.saml-auth2}")
    private String samlAuth2Endpoint;
    
    @Value("${endpoint.health}")
    private String healthEndpoint;
    
    @Value("${endpoint.wallet}")
    private String walletEndpoint;
    
    @Value("${endpoint.treasury}")
    private String treasuryEndpoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    "/.well-known/*",
                    jwksEndpoint,
                    messageEndpoint,
                    walletAuthEndpoint,
                    walletAuth2Endpoint,
                    samlAuthEndpoint,
                    samlAuth2Endpoint,
                    healthEndpoint,
                    walletEndpoint + "/**",
                    treasuryEndpoint + "/**"
                )
            )
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/.well-known/*").permitAll()
                .requestMatchers(jwksEndpoint).permitAll()
                .requestMatchers(messageEndpoint).permitAll()
                .requestMatchers(walletAuthEndpoint).permitAll()
                .requestMatchers(walletAuth2Endpoint).permitAll()
                .requestMatchers(samlAuthEndpoint).permitAll()
                .requestMatchers(samlAuth2Endpoint).permitAll()
                .requestMatchers(healthEndpoint).permitAll()
                // Wallet dashboard static resources (HTML/CSS/JS)
                .requestMatchers("/wallet-dashboard/**").permitAll()
                // ALL wallet endpoints - restricted by CORS to localhost
                .requestMatchers(walletEndpoint + "/**").permitAll()
                .requestMatchers(treasuryEndpoint + "/**").permitAll()
                .anyRequest().denyAll()
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration publicConfiguration = new CorsConfiguration();
        publicConfiguration.setAllowedOrigins(Arrays.asList(allowedOrigins));
        publicConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
        publicConfiguration.addAllowedHeader("*");

        CorsConfiguration walletConfiguration = new CorsConfiguration();
        walletConfiguration.setAllowedOrigins(Arrays.asList(walletAllowedOrigins));
        walletConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
        walletConfiguration.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Public endpoints
        source.registerCorsConfiguration(messageEndpoint, publicConfiguration);
        source.registerCorsConfiguration(walletAuthEndpoint, publicConfiguration);
        source.registerCorsConfiguration(walletAuth2Endpoint, publicConfiguration);
        source.registerCorsConfiguration(samlAuthEndpoint, publicConfiguration);
        source.registerCorsConfiguration(samlAuth2Endpoint, publicConfiguration);
        source.registerCorsConfiguration(healthEndpoint, publicConfiguration);
        
        // ALL wallet endpoints - localhost only, except institutional reservation
        source.registerCorsConfiguration(walletEndpoint + "/**", walletConfiguration);
        source.registerCorsConfiguration(treasuryEndpoint + "/**", walletConfiguration);

        return source;
    }
}
