package org.mangala.security;

/**
 * Constants used across security components.
 */
public final class SecurityConstants {

    private SecurityConstants() {
        // Constants class
    }

    // Header names
    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_USER_EMAIL = "X-User-Email";
    public static final String HEADER_USER_ROLES = "X-User-Roles";
    public static final String HEADER_USER_PERMISSIONS = "X-User-Permissions";
    public static final String HEADER_TENANT_ID = "X-Tenant-Id";
    public static final String HEADER_REQUEST_ID = "X-Request-Id";
    public static final String HEADER_CORRELATION_ID = "X-Correlation-Id";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_FORBIDDEN_REASON = "X-Forbidden-Reason";

    // JWT claim names
    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_PERMISSIONS = "permissions";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_ATTRIBUTES = "attributes";
    public static final String CLAIM_TOKEN_TYPE = "type";
    public static final String CLAIM_TENANT_ID = "tenant_id";

    // Token types
    public static final String TOKEN_TYPE_ACCESS = "access";
    public static final String TOKEN_TYPE_REFRESH = "refresh";

    // Bearer prefix
    public static final String BEARER_PREFIX = "Bearer ";

    // Redis key prefixes
    public static final String REDIS_TOKEN_BLACKLIST_PREFIX = "token:blacklist:";
    public static final String REDIS_POLICY_CACHE_PREFIX = "policy:cache:";
    public static final String REDIS_POLICY_VERSION_KEY = "policy:version";

    // Kafka topics
    public static final String TOPIC_POLICY_UPDATES = "policy-updates";
    public static final String TOPIC_AUTHORIZATION_AUDIT = "audit.authorization";

    // Default values
    public static final int DEFAULT_POLICY_CACHE_SIZE = 10000;
    public static final long DEFAULT_POLICY_CACHE_TTL_SECONDS = 300;
    public static final long DEFAULT_TOKEN_CACHE_TTL_SECONDS = 30;
}
