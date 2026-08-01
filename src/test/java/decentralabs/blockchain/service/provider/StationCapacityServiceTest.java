package decentralabs.blockchain.service.provider;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StationCapacityServiceTest {

    private StationCapacityService service;

    @BeforeEach
    void setUp() {
        service = new StationCapacityService(
            new ObjectMapper(),
            "",
            "",
            100,
            false
        );
    }

    @Test
    void rejectsMissingDeclaredCapacity() {
        assertThatThrownBy(() -> service.validateDeclaredCapacity(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("maxConcurrentUsers is required for FMU resources");
    }

    @Test
    void rejectsNonPositiveDeclaredCapacity() {
        assertThatThrownBy(() -> service.validateDeclaredCapacity(0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("maxConcurrentUsers must be a positive integer");
    }
}
