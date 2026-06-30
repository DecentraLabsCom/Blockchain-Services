package decentralabs.blockchain.controller.labadmin;

import decentralabs.blockchain.dto.labadmin.LabAdminAssetResponse;
import decentralabs.blockchain.dto.labadmin.LabAdminPublishRequest;
import decentralabs.blockchain.dto.labadmin.LabAdminTransactionResponse;
import decentralabs.blockchain.service.auth.JwtService;
import decentralabs.blockchain.service.labadmin.LabAdminService;
import decentralabs.blockchain.util.LogSanitizer;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.HandlerMapping;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;

@RestController
@RequiredArgsConstructor
@Slf4j
public class LabAdminController {

    private final LabAdminService labAdminService;
    private final JwtService jwtService;

    @GetMapping("/lab-admin/status")
    public ResponseEntity<?> status() {
        return ok(labAdminService.status());
    }

    @GetMapping("/lab-admin/labs")
    public ResponseEntity<?> labs() {
        try {
            return ok(labAdminService.listLabs());
        } catch (Exception ex) {
            return badRequest(ex);
        }
    }

    @PostMapping("/lab-admin/assets")
    public ResponseEntity<?> uploadAsset(
        @RequestParam(required = false) String contentId,
        @RequestParam(defaultValue = "images") String kind,
        @RequestParam MultipartFile file
    ) {
        try {
            LabAdminAssetResponse response = labAdminService.saveAsset(contentId, kind, file);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException ex) {
            return badRequest(ex);
        } catch (IOException ex) {
            return internal("Lab content storage is not writable. Check LAB_CONTENT_BASE_PATH and lab-content volume permissions.", ex);
        } catch (Exception ex) {
            return internal("Failed to store asset", ex);
        }
    }

    @DeleteMapping("/lab-admin/assets")
    public ResponseEntity<?> deleteAsset(@RequestBody(required = false) Map<String, String> body) {
        try {
            String path = body == null ? null : body.get("path");
            return ResponseEntity.ok(labAdminService.deleteAsset(path));
        } catch (IllegalArgumentException ex) {
            return badRequest(ex);
        } catch (Exception ex) {
            return internal("Failed to delete asset", ex);
        }
    }

    @PostMapping("/lab-admin/labs")
    public ResponseEntity<?> publish(@RequestBody LabAdminPublishRequest request) {
        try {
            LabAdminTransactionResponse response = labAdminService.publish(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException | IllegalStateException ex) {
            return badRequest(ex);
        } catch (Exception ex) {
            return internal("Failed to publish lab", ex);
        }
    }

    @PutMapping("/lab-admin/labs/{labId}")
    public ResponseEntity<?> update(@PathVariable BigInteger labId, @RequestBody LabAdminPublishRequest request) {
        try {
            LabAdminTransactionResponse response = labAdminService.update(labId, request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException | IllegalStateException ex) {
            return badRequest(ex);
        } catch (Exception ex) {
            return internal("Failed to update lab", ex);
        }
    }

    @DeleteMapping("/lab-admin/labs/{labId}")
    public ResponseEntity<?> deleteLab(@PathVariable BigInteger labId) {
        try {
            LabAdminTransactionResponse response = labAdminService.deleteLab(labId);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException | IllegalStateException ex) {
            return badRequest(ex);
        } catch (Exception ex) {
            return internal("Failed to delete lab", ex);
        }
    }

    @PostMapping("/lab-admin/fmu/provider-describe-token")
    public ResponseEntity<?> fmuProviderDescribeToken(@RequestBody(required = false) Map<String, String> body) {
        try {
            String fmuFileName = body == null ? null : body.get("fmuFileName");
            if (fmuFileName == null || fmuFileName.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing fmuFileName"));
            }
            String trimmed = fmuFileName.strip();
            if (!trimmed.toLowerCase().endsWith(".fmu")) {
                return ResponseEntity.badRequest().body(Map.of("error", "fmuFileName must end with .fmu"));
            }

            long ttlSeconds = 60L;
            long now = Instant.now().getEpochSecond();
            Map<String, Object> claims = new HashMap<>();
            claims.put("accessKey", trimmed);
            claims.put("resourceType", "fmu");
            claims.put("exp", BigInteger.valueOf(now + ttlSeconds));

            String token = jwtService.generateToken(claims, null);
            return ResponseEntity.ok(Map.of("token", token, "expiresIn", ttlSeconds));
        } catch (Exception ex) {
            return internal("Failed to issue FMU describe token", ex);
        }
    }

    @PostMapping("/lab-admin/labs/{labId}/list")
    public ResponseEntity<?> listLab(@PathVariable BigInteger labId) {
        try {
            return ResponseEntity.ok(labAdminService.listLab(labId, true));
        } catch (IllegalArgumentException | IllegalStateException ex) {
            return badRequest(ex);
        } catch (Exception ex) {
            return internal("Failed to list lab", ex);
        }
    }

    @PostMapping("/lab-admin/labs/{labId}/unlist")
    public ResponseEntity<?> unlistLab(@PathVariable BigInteger labId) {
        try {
            return ResponseEntity.ok(labAdminService.listLab(labId, false));
        } catch (IllegalArgumentException | IllegalStateException ex) {
            return badRequest(ex);
        } catch (Exception ex) {
            return internal("Failed to unlist lab", ex);
        }
    }

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

    private ResponseEntity<Map<String, Object>> ok(Map<String, Object> body) {
        return ResponseEntity.ok(body);
    }

    private ResponseEntity<Map<String, Object>> badRequest(Exception ex) {
        return ResponseEntity.badRequest().body(Map.of(
            "success", false,
            "error", ex.getMessage()
        ));
    }

    private ResponseEntity<Map<String, Object>> internal(String clientMessage, Exception ex) {
        String detail = LogSanitizer.sanitize(ex.getMessage());
        log.error("{}: {}", clientMessage, detail, ex);
        return ResponseEntity.internalServerError().body(Map.of(
            "success", false,
            "error", clientMessage,
            "details", detail
        ));
    }
}
