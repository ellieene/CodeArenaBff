package com.example.bff.filter;

import com.example.bff.component.JwtExceptionResponseMapper;
import com.example.bff.config.ServiceConfig;
import com.example.bff.exception.MissingTokenException;
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
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.example.bff.util.CommonStrings.MISSING_USERNAME_HEADER;
import static com.example.bff.util.CommonStrings.MISSING_USER_ID_HEADER;

/**
 * Глобальный фильтр Spring Cloud Gateway для проверки JWT-токенов
 * и авторизации запросов на основе заданных разрешений.
 *
 * <p>Фильтр выполняет:
 * <ul>
 *     <li>Сопоставление запрашиваемого пути и метода HTTP с конфигурацией {@link Permission}</li>
 *     <li>Проверку JWT-токена с помощью {@link JwtService}</li>
 *     <li>Проверку ролей пользователя и при необходимости — соответствия userId</li>
 *     <li>Добавление необходимых заголовков в запрос для передачи в целевой сервис</li>
 *     <li>Обработку ошибок соединения с сервисами</li>
 * </ul>
 * <p>
 * Реализует интерфейсы {@link GlobalFilter} и {@link Ordered},
 * чтобы интегрироваться в цепочку фильтров Spring Cloud Gateway
 * и управлять порядком их выполнения.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    /**
     * Регулярное выражение для поиска UUID в строке.
     */
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");

    /**
     * Сервис для работы с JWT-токенами: валидация, извлечение claims.
     */
    private final JwtService jwtService;
    /**
     * Маппер для формирования ответа при ошибках JWT-аутентификации.
     */
    private final JwtExceptionResponseMapper exceptionResponseMapper;
    /**
     * Объект, содержащий список разрешений для различных URL.
     */
    private final Permission permission;
    /**
     * Конфигурация для определения URI микросервисов.
     */
    private final ServiceConfig serviceConfig;
    /**
     * Сопоставитель путей с поддержкой шаблонов (например, /users/**).
     */
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * Основной метод фильтра, обрабатывающий каждый входящий запрос.
     *
     * <p>Выполняет следующие шаги:
     * <ol>
     *     <li>Определяет разрешение для запроса на основе пути и HTTP-метода</li>
     *     <li>Если разрешение не найдено — возвращает 403 FORBIDDEN</li>
     *     <li>Если проверка разрешений не требуется — пропускает запрос дальше</li>
     *     <li>Извлекает JWT-токен из заголовка Authorization</li>
     *     <li>Валидирует токен и получает claims</li>
     *     <li>Проверяет роль пользователя и соответствие userId при необходимости</li>
     *     <li>Добавляет необходимые заголовки в запрос</li>
     *     <li>Обрабатывает ошибки недоступности сервисов</li>
     * </ol>
     *
     * @param exchange объект с информацией о текущем запросе и ответе
     * @param chain    цепочка фильтров Spring Cloud Gateway
     * @return Mono, сигнализирующий о завершении обработки
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.debug("Incoming request: {} {}",
                exchange.getRequest().getMethod(),
                exchange.getRequest().getPath());

        try {
            URLPermission perm = findPermission(exchange)
                    .orElseThrow(() -> {
                        log.warn("No permission found for path: {}", exchange.getRequest().getPath());
                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        return new RuntimeException("Permission not found");
                    });

            log.debug("Permission matched: {}", perm);

            if (isPermissionIgnored(perm)) {
                log.info("Permission check is ignored for endpoint: {}", perm.getEndpoint());
                return chain.filter(exchange)
                        .onErrorResume(throwable -> handleServiceUnavailable(exchange, throwable, perm.getServiceName()));
            }

            String token = extractToken(exchange);
            Claims claims = validateTokenAndGetClaims(token);

            checkRoleAndOwner(perm, claims, exchange.getRequest().getPath().value());

            ServerHttpRequest mutatedRequest = mutateRequestWithHeaders(exchange, perm, claims);
            return chain.filter(exchange.mutate().request(mutatedRequest).build())
                    .onErrorResume(throwable -> handleServiceUnavailable(exchange, throwable, perm.getServiceName()));

        } catch (JwtException | IllegalArgumentException | AccessDeniedException e) {
            log.error("JWT validation failed: {}", e.getMessage(), e);
            return exceptionResponseMapper.handleJwtException(exchange, e);
        }
    }

    /**
     * Ищет разрешение для запроса на основе пути и HTTP-метода.
     *
     * @param exchange объект текущего запроса
     * @return Optional с найденным разрешением или пустой Optional, если разрешение не найдено
     */
    private Optional<URLPermission> findPermission(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        String method = exchange.getRequest().getMethod().name();

        return permission.getPermissions().stream()
                .filter(p -> pathMatcher.match(p.getEndpoint(), path) && p.getMethod().equalsIgnoreCase(method))
                .findFirst();
    }

    /**
     * Проверяет, требуется ли для эндпоинта проверка разрешений.
     *
     * @param perm разрешение для эндпоинта
     * @return true, если проверка разрешений отключена
     */
    private boolean isPermissionIgnored(URLPermission perm) {
        return perm.isIgnorPermissionCheck();
    }

    /**
     * Извлекает JWT-токен из заголовка Authorization запроса.
     *
     * @param exchange объект текущего запроса
     * @return строка с JWT-токеном
     * @throws MissingTokenException если заголовок отсутствует или некорректен
     */
    private String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Authorization header missing or invalid");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            throw new MissingTokenException("Missing or invalid Authorization header");
        }
        String token = authHeader.substring(7);
        log.debug("Extracted token: {}", token);
        return token;
    }

    /**
     * Валидирует JWT-токен и возвращает claims.
     *
     * @param token JWT-токен
     * @return объект Claims с информацией из токена
     * @throws JwtException если токен недействителен
     */
    private Claims validateTokenAndGetClaims(String token) {
        jwtService.checkToken(token);
        Claims claims = jwtService.getClaims(token);
        log.debug("Token claims: {}", claims);
        return claims;
    }

    /**
     * Проверяет, имеет ли пользователь требуемую роль, и при необходимости — совпадение userId.
     *
     * @param perm   разрешение для эндпоинта
     * @param claims данные из JWT-токена
     * @param path   путь запроса
     * @throws AccessDeniedException если роль не разрешена или userId не совпадает
     */
    private void checkRoleAndOwner(URLPermission perm, Claims claims, String path) throws AccessDeniedException {
        String roleStr = claims.get("role", String.class);
        Role role = Role.valueOf(roleStr);
        log.debug("User role: {}", role);

        if (perm.getRoles() != null && !perm.getRoles().contains(role)) {
            log.warn("Access denied: role {} is not allowed for endpoint {}", role, perm.getEndpoint());
            throw new AccessDeniedException("Role not allowed");
        }

        if (perm.getRoles() != null && perm.getRoles().contains(Role.OWNER)) {
            UUID userId = claims.get("userId", UUID.class);
            if (userId == null) {
                log.warn("Missing userId in token for OWNER role");
                throw new MissingTokenException(MISSING_USER_ID_HEADER);
            }
            accessCheckOwnerUUID(userId, path);
        }
    }

    /**
     * Добавляет в запрос необходимые заголовки для передачи в целевой сервис.
     *
     * @param exchange объект текущего запроса
     * @param perm     разрешение для эндпоинта
     * @param claims   данные из JWT-токена
     * @return изменённый запрос с дополнительными заголовками
     * @throws MissingTokenException если для роли EDIT отсутствует username в токене
     */
    private ServerHttpRequest mutateRequestWithHeaders(ServerWebExchange exchange, URLPermission perm, Claims claims) {
        String serviceUri = serviceConfig.getUri(perm.getServiceName());

        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate()
                .header("X-Username", claims.getSubject())
                .header("X-Role", claims.get("role", String.class))
                .header("X-Service-Uri", serviceUri);

        if (perm.getRoles() != null && perm.getRoles().contains(Role.EDIT)) {
            String username = claims.get("name", String.class);
            if (username == null) {
                log.warn("Missing username in token for EDIT role");
                throw new MissingTokenException(MISSING_USERNAME_HEADER);
            }
            requestBuilder.header("username", username);
        }

        return requestBuilder.build();
    }

    /**
     * Определяет порядок выполнения фильтра в цепочке.
     * Чем меньше значение, тем раньше фильтр будет выполнен.
     *
     * @return порядок выполнения фильтра (-1 — очень высокий приоритет)
     */
    @Override
    public int getOrder() {
        return -1;
    }

    /**
     * Проверяет, что userId из токена совпадает с userId в пути запроса.
     *
     * @param userIdFromHeader userId, извлечённый из JWT-токена
     * @param path             путь запроса
     * @throws AccessDeniedException если userId не совпадают
     */
    private void accessCheckOwnerUUID(UUID userIdFromHeader, String path) throws AccessDeniedException {
        UUID userIdFromEndpoint = UUID.fromString(Objects.requireNonNull(extractUUID(path)));
        if (!userIdFromHeader.equals(userIdFromEndpoint)) {
            throw new AccessDeniedException("");
        }
    }

    /**
     * Извлекает первый UUID из переданной строки.
     *
     * @param input строка для поиска
     * @return найденный UUID в виде строки или null, если UUID отсутствует
     */
    private String extractUUID(String input) {
        Matcher matcher = UUID_PATTERN.matcher(input);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }

    /**
     * Обрабатывает ошибки, связанные с недоступностью целевого сервиса.
     *
     * <p>Если обнаружена ошибка соединения (Connection refused/reset), возвращает
     * клиенту статус 503 Service Unavailable и JSON-ответ с информацией о сервисе.
     *
     * @param exchange    текущий обмен данными (запрос/ответ)
     * @param throwable   выброшенное исключение
     * @param serviceName имя недоступного сервиса
     * @return реактивный Mono, сигнализирующий о завершении ответа
     */
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
                    bytes = "{\"error\":\"Internal Server Error\"}"
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                }

                var buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                return exchange.getResponse().writeWith(Mono.just(buffer));
            }
            cause = cause.getCause();
        }
        return Mono.error(throwable);
    }
}