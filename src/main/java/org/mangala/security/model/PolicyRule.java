package org.mangala.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Represents an API permission policy rule for authorization.
 * Loaded from database and cached in memory at gateway startup.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyRule {

    private String id;
    private String httpMethod;
    private String pathPattern;
    private Set<String> requiredPermissions;
    private String conditionExpr;
    private String serviceName;
    private int priority;
    private transient Pattern compiledPattern;

    /**
     * Creates a cache key for this rule.
     */
    public String getCacheKey() {
        return httpMethod + ":" + pathPattern;
    }
}
