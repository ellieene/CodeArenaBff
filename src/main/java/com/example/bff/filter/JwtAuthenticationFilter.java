package com.example.bff.filter;

import com.example.bff.component.JwtExceptionResponseMapper;
import com.example.bff.component.PermissionLoader;
import com.example.bff.config.ServiceConfig;
import com.example.bff.model.dto.Permission;
import com.example.bff.model.dto.Permission.URLPermission;
import com.example.bff.model.enums.Role;
import com.example.bff.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.file.AccessDeniedException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final PermissionLoader permissionLoader;
    private final JwtService jwtService;
    private final JwtExceptionResponseMapper exceptionResponseMapper;
    private final Permission permission;
    private final ServiceConfig serviceConfig;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private static final Pattern UUID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getPath().value();
        String userMethod = exchange.getRequest().getMethod().name();

        Optional<URLPermission> urlPermission = permission.getPermissions().stream()
                .filter(p -> pathMatcher.match(p.getEndpoint(), path) && p.getMethod().equalsIgnoreCase(userMethod))
                .findFirst();

        if (urlPermission.isEmpty()) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        URLPermission perm = urlPermission.get();
        log.info("Processing request for service: {}", perm.getServiceName());

        String serviceUri = serviceConfig.getUri(perm.getServiceName());
        log.debug("Resolved service URI: {}", serviceUri);

        // Если проверка разрешений не нужна — пропускаем
        if (perm.isIgnorPermissionCheck()) {
            return chain.filter(exchange)
                    .onErrorResume(throwable -> handleServiceUnavailable(exchange, throwable, perm.getServiceName()));
        }

        // Проверка JWT
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            jwtService.checkToken(token);
            Claims claims = jwtService.getClaims(token);
            String userIdHeaderStr = exchange.getRequest().getHeaders().getFirst("userId");

            String roleStr = claims.get("role", String.class);
            Role role = Role.valueOf(roleStr);

            // Проверка ролей
            if (perm.getRoles() != null && !perm.getRoles().contains(role)) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            } else if (perm.getRoles() != null && perm.getRoles().contains(Role.OWNER) && userIdHeaderStr != null) {
                UUID userIdHeader = UUID.fromString(userIdHeaderStr);
                accessCheckOwner(userIdHeader, path);
            }

            ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate()
                    .header("X-Username", claims.getSubject())
                    .header("X-Role", roleStr)
                    .header("X-Service-Uri", serviceUri);

            // Добавляем userId только для конкретных эндпоинтов
            if (perm.getRoles() != null && perm.getRoles().contains(Role.EDIT) && userIdHeaderStr != null) {
                requestBuilder.header("userId", userIdHeaderStr);
                log.info("Added userId header for profile endpoint: {}", userIdHeaderStr);
            }

            ServerHttpRequest mutatedRequest = requestBuilder.build();



            return chain.filter(exchange.mutate().request(mutatedRequest).build())
                    .onErrorResume(throwable -> handleServiceUnavailable(exchange, throwable, perm.getServiceName()));

        } catch (JwtException | IllegalArgumentException | AccessDeniedException e) {
            return exceptionResponseMapper.handleJwtException(exchange, e);
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private void accessCheckOwner(UUID userIdFromHeader, String path) throws AccessDeniedException {
        UUID userIdFromEndpoint = UUID.fromString(extractUUID(path));
        if (!userIdFromHeader.equals(userIdFromEndpoint)) {
            throw new AccessDeniedException("User is not owner");
        }
    }

    private String extractUUID(String input) {
        Matcher matcher = UUID_PATTERN.matcher(input);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }

    private Mono<Void> handleServiceUnavailable(ServerWebExchange exchange, Throwable throwable, String serviceName) {
        Throwable cause = throwable;
        while (cause != null) {
            if (cause instanceof java.net.ConnectException ||
                    (cause.getMessage() != null &&
                            (cause.getMessage().contains("Connection refused") ||
                                    cause.getMessage().contains("Connection reset")))) {

                exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                exchange.getResponse().getHeaders().setContentType(org.springframework.http.MediaType.APPLICATION_JSON);

                Map<String, String> errorBody = Map.of(
                        "error", "Сервер временно недоступен",
                        "server", serviceName
                );

                byte[] bytes;
                try {
                    bytes = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(errorBody);
                } catch (Exception e) {
                    bytes = "{\"error\":\"Internal Server Error\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                }

                var buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                return exchange.getResponse().writeWith(Mono.just(buffer));
            }
            cause = cause.getCause();
        }
        return Mono.error(throwable);
    }
}