package com.example.bff.exception;

import com.example.bff.model.responce.StringResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.file.AccessDeniedException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(MissingTokenException.class)
    public StringResponse handleException(MissingTokenException e) {
        return new StringResponse(e.getMessage());
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(AccessDeniedException.class)
    public StringResponse handleException(AccessDeniedException e) {
        return new StringResponse(e.getMessage());
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(PermissionNotFoundException.class)
    public StringResponse handlePermissionNotFound(PermissionNotFoundException ex) {
        log.warn("Permission check failed: {}", ex.getMessage());
        return new StringResponse(ex.getMessage());
    }

//    @ResponseStatus(HttpStatus.FORBIDDEN)
//    @ExceptionHandler(AccessDeniedException.class)
//    public StringResponse handleException(AccessDeniedException e) {
//        return new StringResponse(e.getMessage());
//    }

}
