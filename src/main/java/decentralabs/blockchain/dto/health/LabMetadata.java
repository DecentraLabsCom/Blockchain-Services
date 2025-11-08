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

    // Availability configuration
    private List<DayOfWeek> availableDays;
    private TimeRange availableHours;
    private Integer maxConcurrentUsers;
    private List<MaintenanceWindow> unavailableWindows;

    // Existing attributes can be added here as needed
    private String category;
    private List<String> keywords;
    private List<Integer> availableTimeSlots;
    private List<String> documentation;
    private List<String> additionalImages;
}
