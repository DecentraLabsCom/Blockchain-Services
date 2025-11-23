package decentralabs.blockchain.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@WebMvcTest(
    controllers = LocalhostOnlyFilterLoopbackOnlyTest.TestController.class,
    properties = "security.allow-private-networks=false"
)
@Import({LocalhostOnlyFilter.class, LocalhostOnlyFilterLoopbackOnlyTest.TestSecurity.class})
@AutoConfigureMockMvc
class LocalhostOnlyFilterLoopbackOnlyTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void walletEndpoint_blockedFromPrivateNetwork() throws Exception {
        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("172.17.0.1"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void walletEndpoint_allowsLoopback() throws Exception {
        mockMvc.perform(post("/wallet/test").with(req -> { req.setRemoteAddr("127.0.0.1"); return req; }))
            .andExpect(status().isOk());
    }

    @Test
    void walletDashboard_blockedFromPublicIp() throws Exception {
        mockMvc.perform(get("/wallet-dashboard/index.html").with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
            .andExpect(status().isForbidden());
    }

    @Test
    void onboarding_remainsOpen() throws Exception {
        mockMvc.perform(post("/onboarding/token/apply").with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
            .andExpect(status().isOk());
    }

    @RestController
    public static class TestController {
        @PostMapping("/wallet/test")
        ResponseEntity<String> wallet() { return ResponseEntity.ok("ok"); }

        @GetMapping("/wallet-dashboard/index.html")
        ResponseEntity<String> walletDashboard() { return ResponseEntity.ok("ok"); }

        @PostMapping("/onboarding/token/apply")
        ResponseEntity<String> onboarding() { return ResponseEntity.ok("ok"); }
    }

    @Configuration
    public static class TestSecurity {
        @Bean
        SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
            return http.build();
        }
    }
}
