package decentralabs.blockchain;

import decentralabs.blockchain.config.BackendOperatingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import jakarta.annotation.Nonnull;
import jakarta.annotation.PostConstruct;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;

import decentralabs.blockchain.security.AccessTokenAuthenticationFilter;
import decentralabs.blockchain.security.PreAuthenticationRateLimitFilter;
import decentralabs.blockchain.security.PublicEndpointRateLimitFilter;
import decentralabs.blockchain.security.SessionObserverAuthenticationFilter;
import decentralabs.blockchain.service.BackendUrlResolver;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${allowed-origins:}")
    private String[] allowedOrigins;

    @Value("${endpoint.jwks:/auth/jwks}")
    private @Nonnull String jwksEndpoint = "/auth/jwks";
    
    @Value("${endpoint.authorize-and-issue:/auth/authorize-and-issue}")
    private @Nonnull String authorizeAndIssueEndpoint = "/auth/authorize-and-issue";

    @Value("${endpoint.checkin-institutional:/auth/checkin-institutional}")
    private @Nonnull String checkinInstitutionalEndpoint = "/auth/checkin-institutional";

    @Value("${endpoint.access-credential:/auth/access-credential}")
    private @Nonnull String accessCredentialEndpoint = "/auth/access-credential";

    @Value("${endpoint.access-code:/auth/access-code}")
    private @Nonnull String accessCodeEndpoint = "/auth/access-code";
    
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

    @Value("${endpoint.fmu-provider-describe-token:/auth/fmu/provider-describe-token}")
    private @Nonnull String fmuProviderDescribeTokenEndpoint = "/auth/fmu/provider-describe-token";

    @Value("${endpoint.fmu-session-ticket:/auth/fmu/session-ticket}")
    private @Nonnull String fmuSessionTicketEndpoint = "/auth/fmu/session-ticket";

    @Value("${security.access-token.required:true}")
    private boolean accessTokenRequired;

    @Value("${features.providers.enabled:false}")
    private boolean providersEnabled;

    @Value("${blockchain.services.mode:}")
    private String configuredOperatingMode;

    private final AccessTokenAuthenticationFilter accessTokenAuthenticationFilter;
    private final PreAuthenticationRateLimitFilter preAuthenticationRateLimitFilter;
    private final PublicEndpointRateLimitFilter publicEndpointRateLimitFilter;
    private final SessionObserverAuthenticationFilter sessionObserverAuthenticationFilter;
    private final BackendUrlResolver backendUrlResolver;

    public SecurityConfig(
        AccessTokenAuthenticationFilter accessTokenAuthenticationFilter,
        PreAuthenticationRateLimitFilter preAuthenticationRateLimitFilter,
        PublicEndpointRateLimitFilter publicEndpointRateLimitFilter,
        SessionObserverAuthenticationFilter sessionObserverAuthenticationFilter,
        BackendUrlResolver backendUrlResolver
    ) {
        this.accessTokenAuthenticationFilter = accessTokenAuthenticationFilter;
        this.preAuthenticationRateLimitFilter = preAuthenticationRateLimitFilter;
        this.publicEndpointRateLimitFilter = publicEndpointRateLimitFilter;
        this.sessionObserverAuthenticationFilter = sessionObserverAuthenticationFilter;
        this.backendUrlResolver = backendUrlResolver;
    }

    @PostConstruct
    void applyConfiguredOperatingMode() {
        providersEnabled = BackendOperatingMode.providerConsumer(configuredOperatingMode, providersEnabled);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    authBasePath + "/.well-known/*",
                    jwksEndpoint,
                    authorizeAndIssueEndpoint,
                    checkinInstitutionalEndpoint,
                    checkinInstitutionalEndpoint + "/status",
                    accessCredentialEndpoint,
                    accessCodeEndpoint + "/**",
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
                    "/institution-config/**",
                    "/lab-admin/**",
                    "/lab-content/**",
                    "/access-audit/internal/**",
                    fmuProviderDescribeTokenEndpoint,
                    fmuSessionTicketEndpoint + "/**"
                )
            )
            .authorizeHttpRequests(authorize -> {
                if (providersEnabled) {
                    authorize.requestMatchers(authorizeAndIssueEndpoint).permitAll();
                    authorize.requestMatchers(accessCredentialEndpoint).permitAll();
                    authorize.requestMatchers(accessCodeEndpoint + "/**").permitAll();
                    authorize.requestMatchers(fmuProviderDescribeTokenEndpoint).permitAll();
                    // Issue validates the booking JWT. Redeem is restricted to a least-privilege,
                    // per-gateway observer credential so a downloaded ticket is not a public oracle.
                    authorize.requestMatchers(HttpMethod.POST, fmuSessionTicketEndpoint + "/redeem")
                        .hasRole("SESSION_OBSERVER");
                    authorize.requestMatchers(HttpMethod.POST, fmuSessionTicketEndpoint + "/issue").permitAll();
                } else {
                    // These routes either issue provider access material or consume it at a
                    // provider gateway.  A consumer-only backend must reject them at the
                    // application security boundary even if a controller mapping is present.
                    authorize.requestMatchers(
                        authorizeAndIssueEndpoint,
                        accessCredentialEndpoint,
                        accessCodeEndpoint + "/**",
                        fmuProviderDescribeTokenEndpoint,
                        fmuSessionTicketEndpoint + "/**"
                    ).denyAll();
                }
                if (providersEnabled) {
                    authorize.requestMatchers("/lab-admin/**").permitAll();
                } else {
                    // Lab administration includes provider reads, writes and local asset
                    // staging.  The mode boundary must be enforced before the localhost
                    // convenience rule and before the generic OPTIONS rule below.
                    authorize.requestMatchers("/lab-admin/**").denyAll();
                }
                // Provider-only routes are decided above this catch-all OPTIONS rule.
                // Consumer-only also omits their CORS registrations, so a preflight
                // receives no provider integration headers.
                authorize.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
                authorize.requestMatchers("/").permitAll();
                authorize.requestMatchers(authBasePath + "/.well-known/*").permitAll();
                authorize.requestMatchers(jwksEndpoint).permitAll();
                authorize.requestMatchers(checkinInstitutionalEndpoint).permitAll();
                authorize.requestMatchers(checkinInstitutionalEndpoint + "/status").permitAll();
                authorize.requestMatchers(healthEndpoint).permitAll();
                authorize.requestMatchers("/actuator/health/**").permitAll();
                authorize.requestMatchers("/actuator/info").permitAll();
                authorize.requestMatchers("/actuator/metrics/**").permitAll();
                authorize.requestMatchers("/actuator/prometheus").permitAll();
                authorize.requestMatchers("/webauthn/**").permitAll();
                authorize.requestMatchers("/onboarding/**").permitAll();
                authorize.requestMatchers("/institution-config/**").permitAll();
                authorize.requestMatchers("/lab-content/**").permitAll();
                authorize.requestMatchers(HttpMethod.POST, "/access-audit/internal/session-observed")
                    .hasRole("SESSION_OBSERVER");
                authorize.requestMatchers("/access-audit/internal/**").hasRole("INTERNAL");
                authorize.requestMatchers(HttpMethod.GET, "/reservations/projection").permitAll();
                authorize.requestMatchers(intentsEndpoint + "/**").permitAll();
                // Wallet dashboard static resources (HTML/CSS/JS)
                authorize.requestMatchers("/wallet-dashboard/**").permitAll();
                // ALL wallet endpoints - restricted by CORS to localhost
                authorize.requestMatchers(walletEndpoint + "/**").permitAll();
                // In provider+consumer deployments, require the INTERNAL-role barrier regardless
                // of whether an access token is configured — this prevents any localhost-reachable
                // caller from hitting admin billing endpoints without a valid token in provider mode.
                // Consumer-only billing remains a local administrative surface, protected by
                // LocalhostOnlyFilter and the configured access-token policy.
                if (providersEnabled) {
                    authorize.requestMatchers(billingEndpoint + "/admin/**").hasRole("INTERNAL");
                } else {
                    authorize.requestMatchers(billingEndpoint + "/admin/**").permitAll();
                }
                authorize.requestMatchers(billingEndpoint + "/**").permitAll();
                authorize.anyRequest().denyAll();
            })
            .addFilterBefore(sessionObserverAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(accessTokenAuthenticationFilter, SessionObserverAuthenticationFilter.class)
            .addFilterBefore(preAuthenticationRateLimitFilter, SessionObserverAuthenticationFilter.class)
            .addFilterAfter(publicEndpointRateLimitFilter, SessionObserverAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public FilterRegistrationBean<PreAuthenticationRateLimitFilter> preAuthenticationRateLimitFilterRegistration(
        PreAuthenticationRateLimitFilter filter
    ) {
        FilterRegistrationBean<PreAuthenticationRateLimitFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<PublicEndpointRateLimitFilter> publicEndpointRateLimitFilterRegistration(
        PublicEndpointRateLimitFilter filter
    ) {
        FilterRegistrationBean<PublicEndpointRateLimitFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration publicConfiguration = new CorsConfiguration();
        publicConfiguration.setAllowedOrigins(buildPublicAllowedOrigins());
        publicConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
        publicConfiguration.addAllowedHeader("*");

        CorsConfiguration labContentConfiguration = new CorsConfiguration();
        labContentConfiguration.setAllowedOrigins(List.of("*"));
        labContentConfiguration.setAllowedMethods(Arrays.asList("GET", "HEAD", "OPTIONS"));
        labContentConfiguration.setAllowedHeaders(List.of("Content-Type"));

        CorsConfiguration walletConfiguration = new CorsConfiguration();
        walletConfiguration.setAllowedOrigins(buildWalletAllowedOrigins());
        walletConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
        walletConfiguration.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Consumer check-in remains public to Marketplace in both modes. Provider
        // access endpoints are only exposed as CORS integrations in provider mode.
        source.registerCorsConfiguration(checkinInstitutionalEndpoint, publicConfiguration);
        source.registerCorsConfiguration(checkinInstitutionalEndpoint + "/status", publicConfiguration);
        if (providersEnabled) {
            source.registerCorsConfiguration(authorizeAndIssueEndpoint, publicConfiguration);
            source.registerCorsConfiguration(accessCredentialEndpoint, publicConfiguration);
            source.registerCorsConfiguration(fmuProviderDescribeTokenEndpoint, publicConfiguration);
        }
        source.registerCorsConfiguration(healthEndpoint, publicConfiguration);
        source.registerCorsConfiguration(intentsEndpoint + "/**", publicConfiguration);
        source.registerCorsConfiguration("/webauthn/**", publicConfiguration);
        // Note: /onboarding/webauthn/** CORS is handled by OpenResty proxy layer
        // Do NOT register it here to avoid duplicate Access-Control-Allow-Origin headers
        
        // ALL wallet endpoints - localhost only
        source.registerCorsConfiguration(walletEndpoint + "/**", walletConfiguration);
        source.registerCorsConfiguration(billingEndpoint + "/**", walletConfiguration);
        if (providersEnabled) {
            source.registerCorsConfiguration("/lab-admin/**", walletConfiguration);
        } else {
            // Keep a matching, empty CORS policy so consumer-only preflights are
            // rejected by CorsFilter instead of falling through as a successful
            // generic OPTIONS request.
            CorsConfiguration deniedLabAdminConfiguration = new CorsConfiguration();
            deniedLabAdminConfiguration.setAllowedOrigins(List.of());
            deniedLabAdminConfiguration.setAllowedMethods(List.of());
            source.registerCorsConfiguration("/lab-admin/**", deniedLabAdminConfiguration);
        }
        source.registerCorsConfiguration("/lab-content/**", labContentConfiguration);
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
