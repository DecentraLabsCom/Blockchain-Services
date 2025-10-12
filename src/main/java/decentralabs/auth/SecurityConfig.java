package decentralabs.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
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
                    healthEndpoint
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
                .anyRequest().denyAll()
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST"));
        configuration.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(messageEndpoint, configuration);
        source.registerCorsConfiguration(walletAuthEndpoint, configuration);
        source.registerCorsConfiguration(walletAuth2Endpoint, configuration);
        source.registerCorsConfiguration(samlAuthEndpoint, configuration);
        source.registerCorsConfiguration(samlAuth2Endpoint, configuration);
        source.registerCorsConfiguration(healthEndpoint, configuration);
        return source;
    }
}
