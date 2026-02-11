package org.mangala.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * Event published when policies are updated.
 * Used to broadcast cache invalidation to all gateway instances.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyUpdateEvent {

    public enum UpdateType {
        FULL_RELOAD,
        INCREMENTAL
    }

    private long version;
    private UpdateType updateType;
    private List<String> affectedPaths;
    private Instant timestamp;
    private String updatedBy;
}
