package com.example.bff.exception;

/**
 * Исключения для Header
 */
public class MissingTokenException extends RuntimeException {
    public MissingTokenException(String message) {
        super(message);
    }

    // Можно добавить дополнительные конструкторы, если нужно
}
