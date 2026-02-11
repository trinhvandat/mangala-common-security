package org.mangala.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.Set;

/**
 * Represents user claims extracted from JWT token.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtUserClaims {

    private String userId;
    private String email;
    private Set<String> roles;
    private Set<String> permissions;
    private Map<String, Object> attributes;
    private long issuedAt;
    private long expiration;
    private String issuer;
    private String tokenId;
}
