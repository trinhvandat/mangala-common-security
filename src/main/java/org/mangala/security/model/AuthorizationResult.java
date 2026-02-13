package org.mangala.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * Result of an authorization decision.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationResult {

    public enum Decision {
        ALLOW,
        DENY,
        NO_POLICY
    }

    private Decision decision;
    private String reason;
    private Set<String> requiredPermissions;
    private String matchedRule;
    private long evaluationTimeMs;

    public static AuthorizationResult allow(String matchedRule) {
        return new AuthorizationResult(
                Decision.ALLOW,
                null,
                null,
                matchedRule,
                0L
        );
    }

    public static AuthorizationResult deny(String reason, Set<String> requiredPermissions) {
        return new AuthorizationResult(
                Decision.DENY,
                reason,
                requiredPermissions,
                null,
                0L
        );
    }

    public static AuthorizationResult noPolicy(String path) {
        return new AuthorizationResult(
                Decision.NO_POLICY,
                "No policy rule found for path: " + path,
                null,
                null,
                0L
        );
    }

    public boolean isAllowed() {
        return decision == Decision.ALLOW;
    }
}
