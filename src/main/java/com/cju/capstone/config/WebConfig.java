package com.cju.capstone.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 개발 중 프론트(Vite, 5173)에서 직접 호출할 때를 위한 CORS 허용.
 * 기본 구성은 Vite 프록시(/api → 8080)를 쓰므로 없어도 동작한다.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("http://localhost:5173", "http://127.0.0.1:5173")
                .allowedMethods("GET", "PUT", "POST", "OPTIONS");
    }
}
