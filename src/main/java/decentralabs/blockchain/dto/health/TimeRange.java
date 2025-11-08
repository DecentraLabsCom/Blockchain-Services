package decentralabs.blockchain.dto.health;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalTime;

/**
 * Represents a time range for lab availability
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TimeRange {
    private LocalTime start;
    private LocalTime end;
}
