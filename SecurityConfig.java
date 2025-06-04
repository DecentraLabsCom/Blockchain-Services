package decentralabs.auth;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
public class SecurityConfig {

    @Value("${serviceprovider.assertion-consumer-location}")
    private String assertionConsumerLocation;
    @Value("${serviceprovider.metadata-location}")
    private String metadataLocation;
    @Value("${serviceprovider.registration-id}")
    private String registrationId;
    @Value("${identityprovider.entity-id}")
    private String entityId;
    @Value("${identityprovider.sso-url}")
    private String ssoUrl;
    @Value("${identityprovider.verification-certificate-path}")
    private String idpVerificationCertificatePath;
    @Value("${private.key.path}")
    private String privateKeyPath;
    @Value("${public.certificate.path}")
    private String certificatePath;
    @Value("${allowed-origins}")
    private String[] allowedOrigins;

    @Component
    public class DefaultSaml2MetadataResolver implements Saml2MetadataResolver {

        private final DefaultRelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

        public DefaultSaml2MetadataResolver(
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
            this.relyingPartyRegistrationResolver = 
                new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        }

        @Override
        public String resolve(RelyingPartyRegistration relyingPartyRegistration) {
            return relyingPartyRegistration.getAssertingPartyDetails().getEntityId();
        }
    }

    @Bean
    @Primary
    public Saml2MetadataResolver saml2MetadataResolver(
        RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        return new DefaultSaml2MetadataResolver(relyingPartyRegistrationRepository);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf
                .ignoringAntMatchers(
                    "/.well-known/*",
                    "/jwks",
                    "/message",
                    "/auth",
                    "/auth2",
                    "/saml2-rediris",
                    "/saml2-metadata"
                )
            )
            .authorizeHttpRequests(authorize -> authorize
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .antMatchers("/.well-known/*").permitAll()
                .antMatchers("/jwks").permitAll()
                .antMatchers("/message").permitAll()
                .antMatchers("/auth").permitAll()
                .antMatchers("/auth2").permitAll()
                .antMatchers("/saml2-metadata").permitAll()
                .antMatchers("/saml2-rediris").permitAll() 
                .antMatchers("/saml2-auth", "/saml2-auth2").authenticated()
                .anyRequest().denyAll()
            )
            .saml2Login();

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST"));
        configuration.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/message", configuration);
        source.registerCorsConfiguration("/auth", configuration);
        source.registerCorsConfiguration("/auth2", configuration);
        return source;
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() 
    throws Exception {
        RelyingPartyRegistration registration = RelyingPartyRegistration
            .withRegistrationId(registrationId)
            .entityId(metadataLocation)
            .assertionConsumerServiceLocation(assertionConsumerLocation)
            .signingX509Credentials(c -> {
                try {
                    c.add(loadSigningCredential());
                } catch (Exception e) {
                    throw new RuntimeException("Failed to load signing credential", e);
                }
            })
            .assertingPartyDetails(party -> party
                .entityId(entityId)
                .singleSignOnServiceLocation(ssoUrl)
                .wantAuthnRequestsSigned(true)
                .verificationX509Credentials(c -> {
                    try {
                        c.add(loadVerificationCredential());
                    } catch (Exception e) {
                        throw new RuntimeException(
                            "Failed to load verification credential", e);
                    }
                })
            )
            .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    private X509Certificate loadCertificate(String certPath) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (var inputStream = Files.newInputStream(Paths.get(certPath))) {
            return (X509Certificate) factory.generateCertificate(inputStream);
        }
    }

    private PrivateKey loadPrivateKey(String keyPath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyPath));
        String key = new String(keyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = java.util.Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private Saml2X509Credential loadSigningCredential() throws Exception { 
        X509Certificate certificate = loadCertificate(certificatePath);
        PrivateKey privateKey = loadPrivateKey(privateKeyPath);
    
        return new Saml2X509Credential(
            privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
    }
    
    private Saml2X509Credential loadVerificationCredential() throws Exception {   
        X509Certificate certificate = loadCertificate(idpVerificationCertificatePath);
    
        return new Saml2X509Credential(
            certificate, Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
    }
}
