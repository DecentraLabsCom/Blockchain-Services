package decentralabs.blockchain.service.provider;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.util.ReflectionTestUtils;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mysql.MySQLContainer;

@Testcontainers(disabledWithoutDocker = true)
class DistributedReservationAvailabilityLockServiceMySqlIntegrationTest {

    @Container
    @SuppressWarnings("resource")
    private static final MySQLContainer MYSQL = new MySQLContainer("mysql:8.4")
        .withDatabaseName("blockchain_services")
        .withUsername("test")
        .withPassword("test");

    private static DriverManagerDataSource dataSource;

    @BeforeAll
    static void initializeDataSource() {
        dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl(MYSQL.getJdbcUrl());
        dataSource.setUsername(MYSQL.getUsername());
        dataSource.setPassword(MYSQL.getPassword());
    }

    @Test
    void twoProviderReplicasCannotEnterTheSameLabCriticalSectionAtOnce() throws Exception {
        DistributedReservationAvailabilityLockService replicaA = service();
        DistributedReservationAvailabilityLockService replicaB = service();
        ReservationAvailabilityLockKey key = new ReservationAvailabilityLockKey(
            BigInteger.valueOf(11155111),
            "0x1234567890abcdef1234567890abcdef12345678",
            BigInteger.valueOf(16)
        );

        CountDownLatch firstEntered = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondEntered = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> first = executor.submit(() -> replicaA.withLock(key, () -> {
                firstEntered.countDown();
                if (!releaseFirst.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("first lock release timed out");
                }
                return null;
            }));

            assertThat(firstEntered.await(10, TimeUnit.SECONDS)).isTrue();
            Future<?> second = executor.submit(() -> replicaB.withLock(key, () -> {
                secondEntered.countDown();
                return null;
            }));

            assertThat(secondEntered.await(500, TimeUnit.MILLISECONDS)).isFalse();
            releaseFirst.countDown();

            first.get(10, TimeUnit.SECONDS);
            second.get(10, TimeUnit.SECONDS);
            assertThat(secondEntered.await(1, TimeUnit.SECONDS)).isTrue();
        } finally {
            releaseFirst.countDown();
            executor.shutdownNow();
        }
    }

    private DistributedReservationAvailabilityLockService service() {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        StaticListableBeanFactory factory = new StaticListableBeanFactory();
        factory.addBean("jdbcTemplate", jdbcTemplate);
        ObjectProvider<JdbcTemplate> provider = factory.getBeanProvider(JdbcTemplate.class);
        DistributedReservationAvailabilityLockService service =
            new DistributedReservationAvailabilityLockService(provider);
        ReflectionTestUtils.setField(service, "lockTimeoutSeconds", 5);
        return service;
    }
}
