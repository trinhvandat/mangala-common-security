package org.mangala.security.util;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Utility class for matching permissions with wildcard support.
 * Supports hierarchical permissions like:
 * - wallets:* matches wallets:read, wallets:create, etc.
 * - admin:users:* matches admin:users:read, admin:users:write
 * - *:* matches everything (dangerous!)
 */
public final class PermissionMatcher {

    private PermissionMatcher() {
        // Utility class
    }

    /**
     * Check if any user permission matches the required permission.
     * Supports wildcard matching.
     *
     * @param userPermissions Set of permissions the user has
     * @param required        The required permission
     * @return true if user has a matching permission
     */
    public static boolean hasPermission(Set<String> userPermissions, String required) {
        if (userPermissions == null || userPermissions.isEmpty() || required == null) {
            return false;
        }

        for (String userPerm : userPermissions) {
            if (matchesSingle(userPerm, required)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if any user permission matches any of the required permissions.
     *
     * @param userPermissions     Set of permissions the user has
     * @param requiredPermissions Set of required permissions (any match = success)
     * @return true if user has at least one matching permission
     */
    public static boolean hasAnyPermission(Set<String> userPermissions, Set<String> requiredPermissions) {
        if (userPermissions == null || userPermissions.isEmpty()) {
            return false;
        }
        if (requiredPermissions == null || requiredPermissions.isEmpty()) {
            return true; // No permissions required
        }

        for (String required : requiredPermissions) {
            if (hasPermission(userPermissions, required)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if user has all required permissions.
     *
     * @param userPermissions     Set of permissions the user has
     * @param requiredPermissions Set of required permissions (all must match)
     * @return true if user has all required permissions
     */
    public static boolean hasAllPermissions(Set<String> userPermissions, Set<String> requiredPermissions) {
        if (requiredPermissions == null || requiredPermissions.isEmpty()) {
            return true; // No permissions required
        }
        if (userPermissions == null || userPermissions.isEmpty()) {
            return false;
        }

        for (String required : requiredPermissions) {
            if (!hasPermission(userPermissions, required)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check if a single user permission matches the required permission.
     * Supports wildcard (*) at any level.
     *
     * Examples:
     * - "wallets:*" matches "wallets:read" -> true
     * - "wallets:*" matches "wallets:delete" -> true
     * - "wallets:read" matches "wallets:*" -> false (user has less)
     * - "admin:*" matches "admin:users:delete" -> true
     * - "*:*" matches anything -> true
     */
    private static boolean matchesSingle(String userPerm, String required) {
        if (userPerm == null || required == null) {
            return false;
        }

        // Exact match
        if (userPerm.equals(required)) {
            return true;
        }

        // Global wildcard
        if ("*".equals(userPerm) || "*:*".equals(userPerm)) {
            return true;
        }

        // Split and compare parts
        String[] userParts = userPerm.split(":");
        String[] reqParts = required.split(":");

        for (int i = 0; i < userParts.length; i++) {
            if ("*".equals(userParts[i])) {
                // Wildcard at this level covers everything below
                return true;
            }
            if (i >= reqParts.length || !userParts[i].equals(reqParts[i])) {
                return false;
            }
        }

        // User permission parts exhausted, check if lengths match
        return userParts.length == reqParts.length;
    }

    /**
     * Compile a path pattern to a regex Pattern.
     * Converts:
     * - {param} to [^/]+
     * - ** to .*
     * - * to [^/]*
     *
     * @param pathPattern The path pattern like /api/v1/wallets/{id}
     * @return Compiled regex Pattern
     */
    public static Pattern compilePathPattern(String pathPattern) {
        if (pathPattern == null) {
            return Pattern.compile(".*");
        }

        String regex = pathPattern
                // Escape regex special chars except * and {}
                .replace(".", "\\.")
                .replace("$", "\\$")
                .replace("^", "\\^")
                .replace("+", "\\+")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replace("[", "\\[")
                .replace("]", "\\]")
                .replace("|", "\\|")
                // Convert path variables {xxx} to [^/]+
                .replaceAll("\\{[^}]+\\}", "[^/]+")
                // Convert ** to .* (greedy match)
                .replace("**", "@@DOUBLE_STAR@@")
                // Convert single * to [^/]* (non-greedy, single segment)
                .replace("*", "[^/]*")
                // Restore ** as .*
                .replace("@@DOUBLE_STAR@@", ".*");

        return Pattern.compile("^" + regex + "$");
    }

    /**
     * Check if a path matches a pattern.
     *
     * @param pattern Compiled pattern
     * @param path    The actual path to match
     * @return true if path matches pattern
     */
    public static boolean matchesPath(Pattern pattern, String path) {
        if (pattern == null || path == null) {
            return false;
        }
        return pattern.matcher(path).matches();
    }

    /**
     * Check if HTTP method matches.
     * "*" matches any method.
     *
     * @param patternMethod The method from policy rule (GET, POST, *, etc.)
     * @param actualMethod  The actual HTTP method
     * @return true if methods match
     */
    public static boolean matchesMethod(String patternMethod, String actualMethod) {
        if (patternMethod == null || actualMethod == null) {
            return false;
        }
        return "*".equals(patternMethod) ||
                patternMethod.equalsIgnoreCase(actualMethod) ||
                patternMethod.contains(actualMethod);
    }
}
