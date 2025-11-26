package decentralabs.blockchain.dto.health;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.DayOfWeek;
import java.util.List;

/**
 * DTO representing lab metadata including availability configuration
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LabMetadata {
    private String name;
    private String description;
    private String image;

    // Timezone and schedule windows (epoch seconds)
    private String timezone;
    private Long opens;   // inclusive, Unix seconds
    private Long closes;  // inclusive, Unix seconds

    // Slot sizes in minutes
    private List<Integer> timeSlots;

    // Availability configuration
    private List<DayOfWeek> availableDays;
    private TimeRange availableHours;
    private Integer maxConcurrentUsers;
    private List<MaintenanceWindow> unavailableWindows;

    // Existing attributes can be added here as needed
    private String category;
    private List<String> keywords;
    private List<String> documentation;
    private List<String> additionalImages;
}
