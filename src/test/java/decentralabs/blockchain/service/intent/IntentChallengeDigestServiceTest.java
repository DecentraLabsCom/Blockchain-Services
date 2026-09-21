package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import decentralabs.blockchain.dto.intent.IntentMeta;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class IntentChallengeDigestServiceTest {

    private static final String VERIFYING_CONTRACT = "0x3333333333333333333333333333333333333333";
    private IntentChallengeDigestService service;

    @BeforeEach
    void setUp() {
        service = new IntentChallengeDigestService(11_155_111L, VERIFYING_CONTRACT);
    }

    @Test
    void buildsTheSharedEip712Vector() {
        IntentChallengeDigestService.Challenge challenge = service.build(
            meta(),
            "User@Example.EDU",
            " UNED.ES "
        );

        assertThat(challenge.scheme()).isEqualTo(IntentChallengeDigestService.SCHEME);
        assertThat(challenge.digestHex())
            .isEqualTo("0x2ff9568eac6c9920fe2da655335746fab5c7efd2586a07603ce6e26a24216c69");
        assertThat(challenge.challengeBase64Url())
            .isEqualTo("L_lWjqxsmSD-LaZVM1dG-rXH79JYagdgPObiaiQhbGk");
        assertThat(challenge.digest()).hasSize(32);
        assertThat(Base64.getUrlDecoder().decode(challenge.challengeBase64Url()))
            .containsExactly(challenge.digest());
        assertThat(challenge.challengeBase64Url()).doesNotContain("user@example.edu", "uned.es");
    }

    @Test
    void changesWhenAnyIntentOrDomainFieldChanges() {
        IntentChallengeDigestService.Challenge baseline = service.build(meta(), "user@example.edu", "uned.es");

        assertThat(service.build(changedMeta(meta(), changed -> changed.setRequestId("0x" + "12".repeat(32))),
            "user@example.edu", "uned.es").digestHex()).isNotEqualTo(baseline.digestHex());
        assertThat(service.build(changedMeta(meta(), changed -> changed.setSigner("0x1234567890abcdef1234567890abcdef12345679")),
            "user@example.edu", "uned.es").digestHex()).isNotEqualTo(baseline.digestHex());
        assertThat(service.build(changedMeta(meta(), changed -> changed.setExecutor("0xabcdefabcdefabcdefabcdefabcdefabcdefabce")),
            "user@example.edu", "uned.es").digestHex()).isNotEqualTo(baseline.digestHex());
        assertThat(service.build(changedMeta(meta(), changed -> changed.setAction(9)),
            "user@example.edu", "uned.es").digestHex()).isNotEqualTo(baseline.digestHex());
        assertThat(service.build(changedMeta(meta(), changed -> changed.setPayloadHash("0x" + "33".repeat(32))),
            "user@example.edu", "uned.es").digestHex()).isNotEqualTo(baseline.digestHex());
        assertThat(service.build(changedMeta(meta(), changed -> changed.setNonce(8L)),
            "user@example.edu", "uned.es").digestHex()).isNotEqualTo(baseline.digestHex());
        assertThat(service.build(changedMeta(meta(), changed -> changed.setRequestedAt(1_700_000_001L)),
            "user@example.edu", "uned.es").digestHex()).isNotEqualTo(baseline.digestHex());
        assertThat(service.build(changedMeta(meta(), changed -> changed.setExpiresAt(1_700_000_901L)),
            "user@example.edu", "uned.es").digestHex()).isNotEqualTo(baseline.digestHex());
        assertThat(service.build(meta(), "other@example.edu", "uned.es").digestHex())
            .isNotEqualTo(baseline.digestHex());
        assertThat(service.build(meta(), "user@example.edu", "otra.edu").digestHex())
            .isNotEqualTo(baseline.digestHex());
        assertThat(new IntentChallengeDigestService(1L, VERIFYING_CONTRACT)
            .build(meta(), "user@example.edu", "uned.es").digestHex())
            .isNotEqualTo(baseline.digestHex());
        assertThat(new IntentChallengeDigestService(11_155_111L, "0x4444444444444444444444444444444444444444")
            .build(meta(), "user@example.edu", "uned.es").digestHex())
            .isNotEqualTo(baseline.digestHex());
    }

    @Test
    void rejectsMissingOrMalformedTrustedInputs() {
        assertThatThrownBy(() -> service.build(null, "user@example.edu", "uned.es"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Missing intent meta");

        IntentMeta malformed = meta();
        malformed.setRequestId("request-id");
        assertThatThrownBy(() -> service.build(malformed, "user@example.edu", "uned.es"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Invalid requestId");
    }

    @Test
    void rejectsNonCanonicalStoredChallenges() {
        IntentChallengeDigestService.Challenge challenge = service.build(meta(), "user@example.edu", "uned.es");

        assertThat(service.matches(challenge, challenge.challengeBase64Url())).isTrue();
        assertThat(service.matches(challenge, challenge.challengeBase64Url() + "=")).isFalse();
        assertThat(service.matches(challenge, "not-base64url")).isFalse();
    }

    private IntentMeta meta() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("0x" + "11".repeat(32));
        meta.setSigner("0x1234567890abcdef1234567890abcdef12345678");
        meta.setExecutor("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
        meta.setAction(8);
        meta.setPayloadHash("0x" + "22".repeat(32));
        meta.setNonce(7L);
        meta.setRequestedAt(1_700_000_000L);
        meta.setExpiresAt(1_700_000_900L);
        return meta;
    }

    private IntentMeta changedMeta(IntentMeta meta, java.util.function.Consumer<IntentMeta> change) {
        change.accept(meta);
        return meta;
    }
}
