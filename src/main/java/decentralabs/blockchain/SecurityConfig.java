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

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf
                .ignoringAntMatchers(
                    "/.well-known/*",
                    jwksEndpoint,
                    messageEndpoint,
                    walletAuthEndpoint,
                    walletAuth2Endpoint,
                    samlAuthEndpoint,
                    samlAuth2Endpoint,
                    healthEndpoint,
                    walletEndpoint + "/**"
                )
            )
            .authorizeHttpRequests(authorize -> authorize
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .antMatchers("/.well-known/*").permitAll()
                .antMatchers(jwksEndpoint).permitAll()
                .antMatchers(messageEndpoint).permitAll()
                .antMatchers(walletAuthEndpoint).permitAll()
                .antMatchers(walletAuth2Endpoint).permitAll()
                .antMatchers(samlAuthEndpoint).permitAll()
                .antMatchers(samlAuth2Endpoint).permitAll()
                .antMatchers(healthEndpoint).permitAll()
                // ALL wallet endpoints - restricted by CORS to localhost
                .antMatchers(walletEndpoint + "/**").permitAll()
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

        CorsConfiguration localhostConfiguration = new CorsConfiguration();
        localhostConfiguration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://127.0.0.1:3000"));
        localhostConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
        localhostConfiguration.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Public endpoints
        source.registerCorsConfiguration(messageEndpoint, publicConfiguration);
        source.registerCorsConfiguration(walletAuthEndpoint, publicConfiguration);
        source.registerCorsConfiguration(walletAuth2Endpoint, publicConfiguration);
        source.registerCorsConfiguration(samlAuthEndpoint, publicConfiguration);
        source.registerCorsConfiguration(samlAuth2Endpoint, publicConfiguration);
        source.registerCorsConfiguration(healthEndpoint, publicConfiguration);
        
        // ALL wallet endpoints - localhost only
        source.registerCorsConfiguration(walletEndpoint + "/**", localhostConfiguration);
        
        return source;
    }
}
