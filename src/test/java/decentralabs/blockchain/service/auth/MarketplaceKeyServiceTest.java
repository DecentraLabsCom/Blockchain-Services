package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

@ExtendWith(MockitoExtension.class)
class MarketplaceKeyServiceTest {

    @Mock
    private RestTemplate restTemplate;

    private MarketplaceKeyService keyService;
    private String validPublicKeyPem;
    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        keyService = new MarketplaceKeyService();
        ReflectionTestUtils.setField(keyService, "restTemplate", restTemplate);
        ReflectionTestUtils.setField(keyService, "marketplacePublicKeyUrl", "https://example.com/public-key");
        ReflectionTestUtils.setField(keyService, "keyCacheDurationMs", 3600000L);
        ReflectionTestUtils.setField(keyService, "keyRetryMs", 60000L);

        // Generate a real RSA key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        testKeyPair = keyGen.generateKeyPair();

        // Convert to PEM format
        byte[] publicKeyBytes = testKeyPair.getPublic().getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(publicKeyBytes);
        validPublicKeyPem = "-----BEGIN PUBLIC KEY-----\n" + base64Key + "\n-----END PUBLIC KEY-----";
    }

    @Nested
    @DisplayName("getPublicKey Tests")
    class GetPublicKeyTests {

        @Test
        @DisplayName("Should fetch and parse public key from URL")
        void shouldFetchAndParsePublicKey() throws Exception {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            PublicKey result = keyService.getPublicKey(false);

            assertThat(result).isNotNull();
            assertThat(result.getAlgorithm()).isEqualTo("RSA");
            verify(restTemplate).getForEntity(anyString(), eq(String.class));
        }

        @Test
        @DisplayName("Should cache key and not refetch within cache duration")
        void shouldCacheKeyAndNotRefetch() throws Exception {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            PublicKey first = keyService.getPublicKey(false);
            PublicKey second = keyService.getPublicKey(false);

            assertThat(first).isSameAs(second);
            verify(restTemplate, times(1)).getForEntity(anyString(), eq(String.class));
        }

        @Test
        @DisplayName("Should force refresh when requested")
        void shouldForceRefreshWhenRequested() throws Exception {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            keyService.getPublicKey(false);
            keyService.getPublicKey(true);

            verify(restTemplate, times(2)).getForEntity(anyString(), eq(String.class));
        }

        @Test
        @DisplayName("Should throw exception when fetch fails")
        void shouldThrowExceptionWhenFetchFails() {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR));

            assertThatThrownBy(() -> keyService.getPublicKey(false))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("Could not fetch marketplace public key");
        }

        @Test
        @DisplayName("Should throw exception when response body is null")
        void shouldThrowExceptionWhenResponseBodyIsNull() {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(null, HttpStatus.OK));

            assertThatThrownBy(() -> keyService.getPublicKey(false))
                .isInstanceOf(Exception.class);
        }

        @Test
        @DisplayName("Should throw exception for invalid PEM format")
        void shouldThrowExceptionForInvalidPemFormat() {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>("invalid-key-data", HttpStatus.OK));

            assertThatThrownBy(() -> keyService.getPublicKey(false))
                .isInstanceOf(Exception.class);
        }

        @Test
        @DisplayName("Should refresh when cache expires")
        void shouldRefreshWhenCacheExpires() throws Exception {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            // Set very short cache duration
            ReflectionTestUtils.setField(keyService, "keyCacheDurationMs", 1L);

            keyService.getPublicKey(false);
            Thread.sleep(10); // Let cache expire
            keyService.getPublicKey(false);

            verify(restTemplate, times(2)).getForEntity(anyString(), eq(String.class));
        }
    }

    @Nested
    @DisplayName("ensureKey Tests")
    class EnsureKeyTests {

        @Test
        @DisplayName("Should return true when key is successfully fetched")
        void shouldReturnTrueWhenKeyFetched() throws Exception {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            boolean result = keyService.ensureKey(false);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should return false when fetch fails")
        void shouldReturnFalseWhenFetchFails() {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenThrow(new RuntimeException("Connection refused"));

            boolean result = keyService.ensureKey(false);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return true when cached key exists")
        void shouldReturnTrueWhenCachedKeyExists() throws Exception {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            keyService.getPublicKey(false);
            boolean result = keyService.ensureKey(false);

            assertThat(result).isTrue();
            verify(restTemplate, times(1)).getForEntity(anyString(), eq(String.class));
        }

        @Test
        @DisplayName("Should force refresh when requested")
        void shouldForceRefreshWhenRequested() throws Exception {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            keyService.getPublicKey(false);
            boolean result = keyService.ensureKey(true);

            assertThat(result).isTrue();
            verify(restTemplate, times(2)).getForEntity(anyString(), eq(String.class));
        }

        @Test
        @DisplayName("Should retry after retry window expires")
        void shouldRetryAfterRetryWindowExpires() throws Exception {
            // Set very short retry window
            ReflectionTestUtils.setField(keyService, "keyRetryMs", 1L);

            // First call fails
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenThrow(new RuntimeException("Connection refused"));
            keyService.ensureKey(false);

            // Setup success for next call
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            Thread.sleep(10); // Let retry window pass
            boolean result = keyService.ensureKey(false);

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("isKeyAvailable Tests")
    class IsKeyAvailableTests {

        @Test
        @DisplayName("Should return false when no key has been fetched")
        void shouldReturnFalseWhenNoKeyFetched() {
            boolean result = keyService.isKeyAvailable();

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return true after successful fetch")
        void shouldReturnTrueAfterSuccessfulFetch() throws Exception {
            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validPublicKeyPem, HttpStatus.OK));

            keyService.getPublicKey(false);
            boolean result = keyService.isKeyAvailable();

            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("Key Parsing Tests")
    class KeyParsingTests {

        @Test
        @DisplayName("Should handle PEM without newlines")
        void shouldHandlePemWithoutNewlines() throws Exception {
            byte[] publicKeyBytes = testKeyPair.getPublic().getEncoded();
            String base64Key = Base64.getEncoder().encodeToString(publicKeyBytes);
            String pemNoNewlines = "-----BEGIN PUBLIC KEY-----" + base64Key + "-----END PUBLIC KEY-----";

            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(pemNoNewlines, HttpStatus.OK));

            PublicKey result = keyService.getPublicKey(false);

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("Should handle PEM with extra whitespace")
        void shouldHandlePemWithExtraWhitespace() throws Exception {
            byte[] publicKeyBytes = testKeyPair.getPublic().getEncoded();
            String base64Key = Base64.getEncoder().encodeToString(publicKeyBytes);
            String pemWithSpaces = "-----BEGIN PUBLIC KEY-----\n  " + base64Key + "  \n-----END PUBLIC KEY-----";

            when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(pemWithSpaces, HttpStatus.OK));

            PublicKey result = keyService.getPublicKey(false);

            assertThat(result).isNotNull();
        }
    }
}
