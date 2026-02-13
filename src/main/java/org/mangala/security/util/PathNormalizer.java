package org.mangala.security.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

/**
 * Utility class for normalizing and validating request paths.
 * Prevents path traversal attacks and ensures consistent matching.
 */
public final class PathNormalizer {

    private PathNormalizer() {
        // Utility class
    }

    /**
     * Normalize a request path for consistent matching.
     * - Decodes URL encoding
     * - Removes double slashes
     * - Resolves . and ..
     * - Converts to lowercase
     *
     * @param path The raw request path
     * @return Normalized path
     */
    public static String normalize(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }

        try {
            // Decode URL encoding
            String decoded = URLDecoder.decode(path, StandardCharsets.UTF_8);

            // Remove double slashes
            decoded = decoded.replaceAll("//+", "/");

            // Resolve . and .. using Paths (but keep as string)
            String normalized = Paths.get(decoded).normalize().toString();

            // Ensure starts with /
            if (!normalized.startsWith("/")) {
                normalized = "/" + normalized;
            }

            // Convert to lowercase for case-insensitive matching
            return normalized.toLowerCase();

        } catch (Exception e) {
            // If decoding fails, return original path lowercase
            return path.toLowerCase();
        }
    }

    /**
     * Check if a path contains potential path traversal attempts.
     *
     * @param path The path to check
     * @return true if path contains traversal patterns
     */
    public static boolean containsTraversal(String path) {
        if (path == null) {
            return false;
        }

        String decoded;
        try {
            decoded = URLDecoder.decode(path, StandardCharsets.UTF_8);
        } catch (Exception e) {
            decoded = path;
        }

        // Check for various traversal patterns
        return decoded.contains("..") ||
                decoded.contains("%2e%2e") ||
                decoded.contains("%2E%2E") ||
                decoded.contains("..%2f") ||
                decoded.contains("..%2F") ||
                decoded.contains("%2f..") ||
                decoded.contains("%2F..");
    }

    /**
     * Validate a path is safe for processing.
     *
     * @param path The path to validate
     * @return true if path is safe
     */
    public static boolean isValidPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }

        // Must start with /
        if (!path.startsWith("/")) {
            return false;
        }

        // Must not contain traversal
        if (containsTraversal(path)) {
            return false;
        }

        // Must not contain null bytes
        if (path.contains("\0") || path.contains("%00")) {
            return false;
        }

        return true;
    }

    /**
     * Extract path variables from a path based on a pattern.
     * Example: pattern="/api/v1/wallets/{walletId}", path="/api/v1/wallets/123"
     * Returns: {walletId: "123"}
     *
     * @param pattern The pattern with {variable} placeholders
     * @param path    The actual path
     * @return Map of variable names to values
     */
    public static java.util.Map<String, String> extractPathVariables(String pattern, String path) {
        java.util.Map<String, String> variables = new java.util.HashMap<>();

        if (pattern == null || path == null) {
            return variables;
        }

        String[] patternParts = pattern.split("/");
        String[] pathParts = path.split("/");

        if (patternParts.length != pathParts.length) {
            return variables;
        }

        for (int i = 0; i < patternParts.length; i++) {
            String patternPart = patternParts[i];
            if (patternPart.startsWith("{") && patternPart.endsWith("}")) {
                String varName = patternPart.substring(1, patternPart.length() - 1);
                variables.put(varName, pathParts[i]);
            }
        }

        return variables;
    }
}
