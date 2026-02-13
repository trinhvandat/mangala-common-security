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
        return AuthorizationResult.builder()
                .decision(Decision.ALLOW)
                .matchedRule(matchedRule)
                .build();
    }

    public static AuthorizationResult deny(String reason, Set<String> requiredPermissions) {
        return AuthorizationResult.builder()
                .decision(Decision.DENY)
                .reason(reason)
                .requiredPermissions(requiredPermissions)
                .build();
    }

    public static AuthorizationResult noPolicy(String path) {
        return AuthorizationResult.builder()
                .decision(Decision.NO_POLICY)
                .reason("No policy rule found for path: " + path)
                .build();
    }

    public boolean isAllowed() {
        return decision == Decision.ALLOW;
    }
}
