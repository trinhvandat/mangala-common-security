package org.mangala.security.preauthenticated;

import lombok.Builder;
import lombok.Getter;

import java.security.Principal;
import java.util.Set;

/**
 * Principal representing a user pre-authenticated by an upstream system (e.g., API gateway).
 * Used by backend services that trust upstream authentication headers.
 *
 * This is a framework-agnostic POJO. Spring Security integration should be
 * implemented in each service that needs it.
 */
@Getter
@Builder
public class PreAuthenticatedPrincipal implements Principal {

    private final String userId;
    private final String email;
    private final Set<String> roles;
    private final Set<String> permissions;

    @Override
    public String getName() {
        return userId;
    }
}
