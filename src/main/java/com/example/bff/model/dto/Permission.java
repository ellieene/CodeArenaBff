package com.example.bff.model.dto;

import com.example.bff.model.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
public class Permission {
    private List<URLPermission> permissions;

    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    public static class URLPermission {
        private String method;
        private String endpoint;
        private String description;
        private boolean ignorPermissionCheck;
        private List<Role> roles;
        private String serviceName;

    }
}
