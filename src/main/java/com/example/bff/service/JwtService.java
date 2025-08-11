package com.example.bff.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String base64Secret;

    private SecretKey secret;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
        this.secret = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Проверяет валидность JWT токена.
     * <p>
     * Проверяет:
     * <ul>
     *   <li>Корректность подписи</li>
     *   <li>Срок действия токена</li>
     *   <li>Общую структуру токена</li>
     * </ul>
     *
     * @param token токен для проверки
     */
    public void checkToken(String token) {
        Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token);
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Извлекает email пользователя из JWT токена.
     *
     * @param token JWT токен для парсинга
     * @return email пользователя, указанный в subject токена
     * @throws JwtException если токен невалиден или не может быть распарсен
     * @throws IllegalArgumentException если токен равен null или пустой
     */
    public String extractEmail(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}