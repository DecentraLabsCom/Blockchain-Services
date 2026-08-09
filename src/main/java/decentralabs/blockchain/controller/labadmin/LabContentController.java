package decentralabs.blockchain.controller.labadmin;

import decentralabs.blockchain.service.labadmin.LabAdminService;
import decentralabs.blockchain.util.LogSanitizer;
import java.io.FileNotFoundException;
import java.time.Duration;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.HandlerMapping;

/** Public, read-only lab content surface shared by provider and consumer deployments. */
@RestController
@RequiredArgsConstructor
@Slf4j
public class LabContentController {

    private final LabAdminService labAdminService;

    @GetMapping("/lab-content/**")
    public ResponseEntity<Resource> content(HttpServletRequest request) {
        try {
            String path = extractWildcardPath(request, "/lab-content/");
            Resource resource = labAdminService.loadContentResource(path);
            String contentType = labAdminService.contentTypeFor(path);
            return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .cacheControl(CacheControl.maxAge(Duration.ofHours(1)).cachePublic())
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type")
                .header("X-Content-Type-Options", "nosniff")
                .body(resource);
        } catch (FileNotFoundException ex) {
            log.debug("Lab content not found", ex);
            return ResponseEntity.notFound().build();
        } catch (Exception ex) {
            log.warn("Failed to serve lab content: {}", LogSanitizer.sanitize(ex.getMessage()));
            return ResponseEntity.badRequest().build();
        }
    }

    private String extractWildcardPath(HttpServletRequest request, String prefix) {
        Object pathWithinMapping = request.getAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE);
        String path = pathWithinMapping == null ? request.getRequestURI() : pathWithinMapping.toString();
        int index = path.indexOf(prefix);
        if (index >= 0) {
            return path.substring(index + prefix.length());
        }
        return "";
    }
}
