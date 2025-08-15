package com.example.bff.component;

import com.example.bff.model.responce.StringResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.file.AccessDeniedException;

import static com.example.bff.util.CommonStrings.*;

@Component
@RequiredArgsConstructor
public class JwtExceptionResponseMapper {

    private final ObjectMapper objectMapper;

    /**
     * Обрабатывает JWT исключение и отправляет JSON-ответ клиенту через WebFlux.
     *
     * @param exchange текущий WebExchange
     * @param e        исключение
     * @return Mono<Void>
     */
    public Mono<Void> handleJwtException(ServerWebExchange exchange, Exception e) {
        int status = mapToStatusCode(e);
        String message = mapToMessage(e);

        exchange.getResponse().setStatusCode(HttpStatus.valueOf(status));
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        StringResponse errorResponse = new StringResponse(message);

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);
            return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                    .bufferFactory().wrap(bytes)));
        } catch (Exception ex) {
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }
    }

    /**
     * Возвращает сообщение об ошибке на основе типа исключения.
     *
     * @param e исключение JWT
     * @return строка с сообщением
     */
    private String mapToMessage(Exception e) {
        if (e instanceof ExpiredJwtException) return EXPIRED_JWT_EXCEPTION;
        if (e instanceof UnsupportedJwtException) return UNSUPPORTED_JWT_EXCEPTION;
        if (e instanceof MalformedJwtException) return MALFORMED_JWT_EXCEPTION;
        if (e instanceof SignatureException) return SIGNATURE_EXCEPTION;
        if (e instanceof IllegalArgumentException) return ILLEGAL_ARGUMENT_EXCEPTION;
        return JWT_EXCEPTION;
    }

    /**
     * Возвращает соответствующий HTTP-статус на основе типа исключения.
     *
     * @param e исключение JWT
     * @return HTTP статус
     */
    private int mapToStatusCode(Exception e) {
        if (e instanceof IllegalArgumentException) return HttpStatus.BAD_REQUEST.value();
        return HttpStatus.UNAUTHORIZED.value();
    }
}