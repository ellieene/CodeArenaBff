package com.example.bff.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteDefinitionLocator;
import org.springframework.cloud.gateway.route.RouteLocator;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Configuration
public class GatewayConfigLogger {
    private static final Logger log = LoggerFactory.getLogger(GatewayConfigLogger.class);

    @Autowired
    public void logRoutes(RouteDefinitionLocator locator) {
        locator.getRouteDefinitions()
                .subscribe(route -> log.info("Route id: {}, uri: {}", route.getId(), route.getUri()));
    }
}