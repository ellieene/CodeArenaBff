package com.example.bff.exception;

import com.example.bff.model.responce.StringResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.nio.file.AccessDeniedException;

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

//    @ResponseStatus(HttpStatus.FORBIDDEN)
//    @ExceptionHandler(AccessDeniedException.class)
//    public StringResponse handleException(AccessDeniedException e) {
//        return new StringResponse(e.getMessage());
//    }

}
