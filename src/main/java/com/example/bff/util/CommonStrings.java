package com.example.bff.util;

import lombok.experimental.UtilityClass;

@UtilityClass
public class CommonStrings {

    public static final String UNCORRECT_PASSWORD = "Неверный пароль.";
    public static final String UNCORRECT_EMAIL_AND_LOGIN = "Почта или логин не верный.";
    public static final String NOT_FOUND_USER = "Пользователь не найден";
    public static final String LOGIN_IS_TAKEN = "Логин уже занят.";
    public static final String EMAIL_IS_TAKEN = "Почта уже занята.";
    public static final String EDIT_USER_SUCCESSES = "Пользователь успешно обновлен";
    public static final String EDIT_PASSWORD_USER_SUCCESSES = "Пароль успешно обновлен";
    public static final String ACCESS_DENIED = "Доступ запрещен";


    // Константы с сообщениями об ошибках с JWT токеном
    public static final String AUTHENTICATION_CREDENTIALS_NOT_FOUND_EXCEPTION = "Токен не предоставлен";
    public static final String EXPIRED_JWT_EXCEPTION = "Срок действия токена истек";
    public static final String UNSUPPORTED_JWT_EXCEPTION = "Неподдерживаемый токен";
    public static final String MALFORMED_JWT_EXCEPTION = "Неверный токен";
    public static final String SIGNATURE_EXCEPTION = "Неверная подпись токена";
    public static final String ILLEGAL_ARGUMENT_EXCEPTION = "Неверный токен";
    public static final String JWT_EXCEPTION = "Ошибка с токеном";

}
