package tools;

import java.io.IOException;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ListJar {
    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("Usage: java tools.ListJar <jar-path> <pattern>");
            System.exit(1);
        }
        Path jar = Path.of(args[0]);
        String pattern = args[1];
        try (ZipFile z = new ZipFile(jar.toFile())) {
            z.stream()
             .map(ZipEntry::getName)
             .filter(n -> n.contains(pattern))
             .forEach(System.out::println);
        }
    }
}
