package org.mangala.security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for API permission data transferred from database.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiPermissionDTO {

    private String id;
    private String httpMethod;
    private String pathPattern;
    private String permissionCode;
    private String conditionExpr;
    private String serviceName;
    private int priority;
    private boolean active;
}
