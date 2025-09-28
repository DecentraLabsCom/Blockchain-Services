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
    
    @Value("${endpoint.auth}")
    private String authEndpoint;
    
    @Value("${endpoint.auth2}")
    private String auth2Endpoint;
    
    @Value("${endpoint.jwks}")
    private String jwksEndpoint;
    
    @Value("${endpoint.message}")
    private String messageEndpoint;
    
    @Value("${endpoint.marketplace-auth}")
    private String marketplaceAuthEndpoint;
    
    @Value("${endpoint.marketplace-auth2}")
    private String marketplaceAuth2Endpoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf
                .ignoringAntMatchers(
                    "/.well-known/*",
                    jwksEndpoint,
                    messageEndpoint,
                    authEndpoint,
                    auth2Endpoint,
                    marketplaceAuthEndpoint,
                    marketplaceAuth2Endpoint
                )
            )
            .authorizeHttpRequests(authorize -> authorize
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .antMatchers("/.well-known/*").permitAll()
                .antMatchers(jwksEndpoint).permitAll()
                .antMatchers(messageEndpoint).permitAll()
                .antMatchers(authEndpoint).permitAll()
                .antMatchers(auth2Endpoint).permitAll()
                .antMatchers(marketplaceAuthEndpoint).permitAll()
                .antMatchers(marketplaceAuth2Endpoint).permitAll()
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
        source.registerCorsConfiguration(authEndpoint, configuration);
        source.registerCorsConfiguration(auth2Endpoint, configuration);
        source.registerCorsConfiguration(marketplaceAuthEndpoint, configuration);
        source.registerCorsConfiguration(marketplaceAuth2Endpoint, configuration);
        return source;
    }
}
