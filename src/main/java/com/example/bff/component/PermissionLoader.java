package com.example.bff.component;

import com.example.bff.model.dto.Permission;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.IOUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.nio.charset.Charset;

@Configuration
public class PermissionLoader {

    /**
     * Загрузчик конфигурации разрешений для API-эндпоинтов.
     */
    @Bean
    public Permission init() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        InputStream is = getClass().getResourceAsStream("/permissions.json");
        String book =
                IOUtils.readInputStreamToString(is, Charset.defaultCharset());
        return mapper.readValue(book, Permission.class);
    }
}
