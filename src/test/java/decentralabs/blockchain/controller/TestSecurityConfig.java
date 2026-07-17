package decentralabs.blockchain.controller;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.SecurityFilterChain;


/**
 * Test-only security configuration for controller integration tests.
 * Production security configuration is not replaced by this class.
 */
@TestConfiguration
@EnableWebSecurity
public class TestSecurityConfig {

    @Bean
    public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(new HttpSessionCsrfTokenRepository())
                // Standalone MockMvc does not share the application session used by the
                // CSRF test post-processor; keep the wallet-operation fixture focused on
                // controller behavior while leaving CSRF enabled for all other requests.
                .ignoringRequestMatchers("/wallet/import", "/wallet/switch-network"))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
