package com.oozma.springsecurity.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {

    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),

    OPERATOR_READ("management:read"),
    OPERATOR_UPDATE("management:update"),
    OPERATOR_CREATE("management:create"),
    OPERATOR_DELETE("management:delete")

    ;

    @Getter
    private final String permission;

}
