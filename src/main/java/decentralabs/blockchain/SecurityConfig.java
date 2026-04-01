package decentralabs.blockchain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import jakarta.annotation.Nonnull;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;

import decentralabs.blockchain.security.AccessTokenAuthenticationFilter;
import decentralabs.blockchain.service.BackendUrlResolver;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${allowed-origins:}")
    private String[] allowedOrigins;

    @Value("${endpoint.jwks:/auth/jwks}")
    private @Nonnull String jwksEndpoint = "/auth/jwks";
    
    @Value("${endpoint.saml-auth:/auth/saml-auth}")
    private @Nonnull String samlAuthEndpoint = "/auth/saml-auth";
    
    @Value("${endpoint.saml-auth2:/auth/saml-auth2}")
    private @Nonnull String samlAuth2Endpoint = "/auth/saml-auth2";

    @Value("${endpoint.checkin-institutional:/auth/checkin-institutional}")
    private @Nonnull String checkinInstitutionalEndpoint = "/auth/checkin-institutional";
    
    @Value("${endpoint.health:/health}")
    private @Nonnull String healthEndpoint = "/health";
    
    @Value("${endpoint.wallet:/wallet}")
    private @Nonnull String walletEndpoint = "/wallet";
    
    @Value("${endpoint.billing:/billing}")
    private @Nonnull String billingEndpoint = "/billing";
    
    @Value("${endpoint.intents:/intents}")
    private @Nonnull String intentsEndpoint = "/intents";

    @Value("${auth.base-path:/auth}")
    private @Nonnull String authBasePath = "/auth";

    @Value("${security.access-token.required:true}")
    private boolean accessTokenRequired;

    private final AccessTokenAuthenticationFilter accessTokenAuthenticationFilter;
    private final BackendUrlResolver backendUrlResolver;

    public SecurityConfig(
        AccessTokenAuthenticationFilter accessTokenAuthenticationFilter,
        BackendUrlResolver backendUrlResolver
    ) {
        this.accessTokenAuthenticationFilter = accessTokenAuthenticationFilter;
        this.backendUrlResolver = backendUrlResolver;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    authBasePath + "/.well-known/*",
                    jwksEndpoint,
                    samlAuthEndpoint,
                    samlAuth2Endpoint,
                    checkinInstitutionalEndpoint,
                    healthEndpoint,
                    "/actuator/health/**",
                    "/actuator/info",
                    "/actuator/metrics/**",
                    "/actuator/prometheus",
                    walletEndpoint + "/**",
                    billingEndpoint + "/**",
                    "/webauthn/**",
                    intentsEndpoint + "/**",
                    "/onboarding/**",
                    "/institution-config/**"
                )
            )
            .authorizeHttpRequests(authorize -> {
                authorize.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
                authorize.requestMatchers("/").permitAll();
                authorize.requestMatchers(authBasePath + "/.well-known/*").permitAll();
                authorize.requestMatchers(jwksEndpoint).permitAll();
                authorize.requestMatchers(samlAuthEndpoint).permitAll();
                authorize.requestMatchers(samlAuth2Endpoint).permitAll();
                authorize.requestMatchers(checkinInstitutionalEndpoint).permitAll();
                authorize.requestMatchers(healthEndpoint).permitAll();
                authorize.requestMatchers("/actuator/health/**").permitAll();
                authorize.requestMatchers("/actuator/info").permitAll();
                authorize.requestMatchers("/actuator/metrics/**").permitAll();
                authorize.requestMatchers("/actuator/prometheus").permitAll();
                authorize.requestMatchers("/webauthn/**").permitAll();
                authorize.requestMatchers("/onboarding/**").permitAll();
                authorize.requestMatchers("/institution-config/**").permitAll();
                authorize.requestMatchers(intentsEndpoint + "/**").permitAll();
                // Wallet dashboard static resources (HTML/CSS/JS)
                authorize.requestMatchers("/wallet-dashboard/**").permitAll();
                // ALL wallet endpoints - restricted by CORS to localhost
                authorize.requestMatchers(walletEndpoint + "/**").permitAll();
                if (accessTokenRequired) {
                    authorize.requestMatchers(billingEndpoint + "/admin/**").hasRole("INTERNAL");
                } else {
                    authorize.requestMatchers(billingEndpoint + "/admin/**").permitAll();
                }
                authorize.requestMatchers(billingEndpoint + "/**").permitAll();
                authorize.anyRequest().denyAll();
            })
            .addFilterBefore(accessTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration publicConfiguration = new CorsConfiguration();
        publicConfiguration.setAllowedOrigins(buildPublicAllowedOrigins());
        publicConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
        publicConfiguration.addAllowedHeader("*");

        CorsConfiguration walletConfiguration = new CorsConfiguration();
        walletConfiguration.setAllowedOrigins(buildWalletAllowedOrigins());
        walletConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
        walletConfiguration.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Public endpoints
        source.registerCorsConfiguration(samlAuthEndpoint, publicConfiguration);
        source.registerCorsConfiguration(samlAuth2Endpoint, publicConfiguration);
        source.registerCorsConfiguration(checkinInstitutionalEndpoint, publicConfiguration);
        source.registerCorsConfiguration(healthEndpoint, publicConfiguration);
        source.registerCorsConfiguration(intentsEndpoint + "/**", publicConfiguration);
        source.registerCorsConfiguration("/webauthn/**", publicConfiguration);
        // Note: /onboarding/webauthn/** CORS is handled by OpenResty proxy layer
        // Do NOT register it here to avoid duplicate Access-Control-Allow-Origin headers
        
        // ALL wallet endpoints - localhost only
        source.registerCorsConfiguration(walletEndpoint + "/**", walletConfiguration);
        source.registerCorsConfiguration(billingEndpoint + "/**", walletConfiguration);
        // Token-based onboarding (invite tokens) - localhost only
        source.registerCorsConfiguration("/onboarding/token/**", walletConfiguration);

        return source;
    }

    private List<String> buildPublicAllowedOrigins() {
        Set<String> origins = new LinkedHashSet<>();
        if (allowedOrigins != null) {
            for (String origin : allowedOrigins) {
                String normalized = normalizeOrigin(origin);
                if (normalized != null) {
                    origins.add(normalized);
                }
            }
        }

        String gatewayOrigin = normalizeOrigin(backendUrlResolver.resolveBaseDomain());
        if (gatewayOrigin != null) {
            origins.add(gatewayOrigin);
        }

        return new ArrayList<>(origins);
    }

    private List<String> buildWalletAllowedOrigins() {
        Set<String> origins = new LinkedHashSet<>();
        if (allowedOrigins != null) {
            for (String origin : allowedOrigins) {
                String normalized = normalizeOrigin(origin);
                if (normalized != null) {
                    origins.add(normalized);
                }
            }
        }

        String gatewayOrigin = normalizeOrigin(backendUrlResolver.resolveBaseDomain());
        if (gatewayOrigin != null) {
            origins.add(gatewayOrigin);
        }

        return new ArrayList<>(origins);
    }

    private String normalizeOrigin(String origin) {
        if (origin == null) {
            return null;
        }
        String trimmed = origin.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.isEmpty() ? null : trimmed;
    }
}
