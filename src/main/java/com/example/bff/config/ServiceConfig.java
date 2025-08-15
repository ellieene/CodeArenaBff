package com.example.bff.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "services")
public class ServiceConfig {
    private Map<String, String> uri = new HashMap<>();

    public String getUri(String serviceName) {
        return uri.get(serviceName);
    }

    public void setUri(Map<String, String> uri) {
        this.uri = uri;
    }
}
