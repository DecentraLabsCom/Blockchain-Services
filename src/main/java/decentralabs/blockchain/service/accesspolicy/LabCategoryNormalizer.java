package decentralabs.blockchain.service.accesspolicy;

import java.text.Normalizer;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class LabCategoryNormalizer {
    private static final List<String> CATEGORIES = List.of(
        "Mathematics", "Statistics & Probability", "Computer Science", "Artificial Intelligence & Machine Learning",
        "Data Science", "Cybersecurity", "Software Engineering", "Physics", "Nuclear Physics", "Particle Physics",
        "Astronomy & Astrophysics", "Optics & Photonics", "Condensed Matter Physics", "Chemistry", "Organic Chemistry",
        "Inorganic Chemistry", "Physical Chemistry", "Analytical Chemistry", "Biochemistry", "Pharmaceutical Chemistry",
        "Geology", "Geophysics", "Meteorology", "Oceanography", "Environmental Sciences", "Climate Science", "Biology",
        "Molecular Biology", "Cell Biology", "Genetics", "Microbiology", "Botany", "Zoology", "Ecology", "Marine Biology",
        "Neuroscience", "Biotechnology", "Engineering & Technology", "Civil Engineering", "Mechanical Engineering", "Electrical Engineering",
        "Electronic Engineering", "Telecommunications Engineering", "Chemical Engineering", "Materials Engineering",
        "Aerospace Engineering", "Robotics", "Automation & Control Systems", "Nanotechnology", "Biomedical Engineering",
        "Medicine", "Clinical Medicine", "Pharmacology", "Toxicology", "Pathology", "Immunology", "Public Health", "Nursing",
        "Medical Imaging", "Laboratory Medicine", "Agriculture", "Animal Science", "Veterinary Medicine", "Forestry", "Fisheries",
        "Soil Science", "Agricultural Engineering", "Psychology", "Experimental Psychology", "Cognitive Science", "Economics",
        "Experimental Economics", "Sociology", "Political Science", "Anthropology", "Linguistics", "Computational Linguistics",
        "Digital Humanities", "Archaeology", "Environmental Engineering", "Energy Engineering", "Renewable Energy",
        "Food Science & Technology", "Quality Control", "Metrology", "Other"
    );
    private static final Map<String, String> CANONICAL_BY_KEY;

    static {
        Map<String, String> values = new LinkedHashMap<>();
        for (String category : CATEGORIES) values.put(key(category), category);
        values.put(key("AI/ML"), "Artificial Intelligence & Machine Learning");
        values.put(key("AI and ML"), "Artificial Intelligence & Machine Learning");
        values.put(key("computer-science"), "Computer Science");
        values.put(key("cyber security"), "Cybersecurity");
        values.put(key("engineering"), "Engineering & Technology");
        CANONICAL_BY_KEY = Collections.unmodifiableMap(values);
    }

    private LabCategoryNormalizer() {}

    public static List<String> normalize(Object raw) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        collect(raw, result);
        return List.copyOf(result);
    }

    public static List<String> recognized(List<String> raw) {
        if (raw == null) return List.of();
        return raw.stream().map(LabCategoryNormalizer::canonical).filter(java.util.Objects::nonNull).distinct().toList();
    }

    public static String canonical(String value) {
        return value == null ? null : CANONICAL_BY_KEY.get(key(value));
    }

    public static String key(String value) {
        String normalized = Normalizer.normalize(value == null ? "" : value, Normalizer.Form.NFKD)
            .replaceAll("\\p{M}", "").toLowerCase(Locale.ROOT).replace('&', ' ');
        return normalized.replaceAll("[^a-z0-9]+", "").trim();
    }

    private static void collect(Object raw, Set<String> result) {
        if (raw == null) return;
        if (raw instanceof Collection<?> collection) {
            collection.forEach(item -> collect(item, result));
            return;
        }
        if (raw instanceof Map<?, ?> map) {
            collect(map.get("category"), result);
            collect(map.get("categories"), result);
            return;
        }
        String canonical = canonical(String.valueOf(raw).trim());
        if (canonical != null) result.add(canonical);
    }
}
