package com.example.bff.model.enums;

import java.util.Arrays;
import java.util.UUID;

public enum Server {
    PROFILE_SERVER ("Profile Service"),
    AUTHENTIFICATION_SERVER ("Authentication Service"),
    ARTICLE ("Article Service");

    private String title;

    Server(String title) {
        this.title = title;
    }

    public String getTitle() {
        return title;
    }

    public static Server fromTitle(String title) {
        return Arrays.stream(Server.values())
                .filter(s -> s.title.equalsIgnoreCase(title))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Сервер не найден - " + title));
    }
}
