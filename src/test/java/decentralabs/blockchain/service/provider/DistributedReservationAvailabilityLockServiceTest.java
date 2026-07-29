package decentralabs.blockchain.service.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DistributedReservationAvailabilityLockServiceTest {

    private final ObjectProvider<JdbcTemplate> jdbcTemplateProvider = mock();
    private final JdbcTemplate jdbcTemplate = mock();
    private final Connection connection = mock();
    private final PreparedStatement acquireStatement = mock();
    private final PreparedStatement releaseStatement = mock();
    private final ResultSet acquireResult = mock();
    private final ResultSet releaseResult = mock();

    private DistributedReservationAvailabilityLockService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new DistributedReservationAvailabilityLockService(jdbcTemplateProvider);
        ReflectionTestUtils.setField(service, "lockTimeoutSeconds", 2);

        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.execute(any(ConnectionCallback.class))).thenAnswer(invocation -> {
            ConnectionCallback<?> callback = invocation.getArgument(0);
            return callback.doInConnection(connection);
        });
        when(connection.prepareStatement("SELECT GET_LOCK(?, ?)")).thenReturn(acquireStatement);
        when(connection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(releaseStatement);
        when(acquireStatement.executeQuery()).thenReturn(acquireResult);
        when(releaseStatement.executeQuery()).thenReturn(releaseResult);
        when(acquireResult.next()).thenReturn(true);
        when(acquireResult.getInt(1)).thenReturn(1);
        when(releaseResult.next()).thenReturn(true);
        when(releaseResult.getInt(1)).thenReturn(1);
    }

    @Test
    void holdsTheConnectionWhileTheProtectedActionRunsAndReleasesTheLockAfterwards() throws Exception {
        ReservationAvailabilityLockKey key = key(16);

        service.withLock(key, () -> {
            verify(acquireStatement).executeQuery();
            return null;
        });

        verify(acquireStatement).setInt(2, 2);
        ArgumentCaptor<String> lockName = ArgumentCaptor.forClass(String.class);
        verify(releaseStatement).setString(eq(1), lockName.capture());
        assertThat(lockName.getValue()).hasSize(64);
        verify(releaseStatement).executeQuery();
    }

    @Test
    void doesNotRunTheActionWhenMySqlCannotAcquireTheLock() throws Exception {
        when(acquireResult.getInt(1)).thenReturn(0);
        var action = mock(DistributedReservationAvailabilityLockService.LockAction.class);

        assertThatThrownBy(() -> service.withLock(key(16), action))
            .isInstanceOf(DistributedReservationAvailabilityLockService.DistributedLockException.class)
            .hasMessageContaining("lock timeout");

        verify(action, never()).run();
        verify(releaseStatement, never()).executeQuery();
    }

    @Test
    void failsClosedWhenNoJdbcTemplateIsAvailable() {
        when(jdbcTemplateProvider.getIfAvailable()).thenReturn(null);

        assertThatThrownBy(() -> service.withLock(key(16), () -> null))
            .isInstanceOf(DistributedReservationAvailabilityLockService.DistributedLockException.class)
            .hasMessageContaining("JdbcTemplate");
    }

    @Test
    void releasesTheLockWhenTheProtectedActionFailsAndPropagatesTheOriginalException() throws Exception {
        Exception failure = new Exception("on-chain failure");

        assertThatThrownBy(() -> service.withLock(key(16), () -> {
            throw failure;
        }))
            .isSameAs(failure);

        verify(releaseStatement).executeQuery();
    }

    @Test
    void derivesDifferentNamesForDifferentLabsWithinTheSameChainAndContract() {
        assertThat(service.lockNameFor(key(16)))
            .isNotEqualTo(service.lockNameFor(key(17)))
            .hasSize(64);
    }

    private ReservationAvailabilityLockKey key(long labId) {
        return new ReservationAvailabilityLockKey(
            BigInteger.valueOf(11155111),
            "0x1234567890abcdef1234567890abcdef12345678",
            BigInteger.valueOf(labId)
        );
    }
}
