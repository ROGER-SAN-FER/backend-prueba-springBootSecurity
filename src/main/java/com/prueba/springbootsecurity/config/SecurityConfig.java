package com.prueba.springbootsecurity.config;

import com.prueba.springbootsecurity.features.audit.handler.AuditAccessDeniedHandler;
import com.prueba.springbootsecurity.features.audit.handler.AuditAuthenticationEntryPoint;
import com.prueba.springbootsecurity.features.auth.filter.JwtAuthenticationFilter;
import com.prueba.springbootsecurity.features.oauth2.handler.OAuth2AuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity // habilita @PreAuthorize, @PostAuthorize, etc.
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final OAuth2AuthenticationSuccessHandler successHandler;
    // inyecta:
    private final AuditAccessDeniedHandler auditDeniedHandler;
    private final AuditAuthenticationEntryPoint auditEntryPoint;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager(); // usa tu JpaUserDetailsService + BCrypt
    }

    /* CORS global (ajusta orígenes según tu frontend) */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();

        // Lista explícita de frontends permitidos
        cfg.setAllowedOrigins(List.of(
                "http://localhost:5173",
                "http://localhost:4200",
                "http://localhost:3000"
        ));

        // Métodos que realmente usas
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        // Headers que tu frontend envía (incluye Authorization para Bearer)
        cfg.setAllowedHeaders(List.of("Authorization","Content-Type","Accept","X-Requested-With"));

        // Si vas a usar cookies/credenciales cross-site (no es tu caso con Bearer, normalmente false)
        cfg.setAllowCredentials(false);

        // Cachea la preflight en el navegador
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }

    // Cadena 1: API (stateless + Bearer con tu JWT)
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(auditEntryPoint)     // 401 con auditoría
                        .accessDeniedHandler(auditDeniedHandler)       // 403 con auditoría
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/refresh").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/logout").permitAll() // o .authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/public/**").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/*").hasRole("ADMIN")
                        .requestMatchers("/api/reports/sensitive").hasRole("ADMIN")
                        .requestMatchers("/api/reports/user").hasAnyRole("USER","ADMIN")
                        .requestMatchers("/api/reports/user/ultraSensible").hasAnyRole("USER","ADMIN")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // Cadena 2: Web (OAuth2 login: Google/Facebook)
    @Bean
    @Order(2)
    SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**", "/oauth2/**", "/login/**").permitAll()
                        .requestMatchers("/me").authenticated()
                        .anyRequest().permitAll()
                )
                .oauth2Login(oauth -> oauth.successHandler(successHandler))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
        // OJO: NO añadir jwtFilter aquí
        return http.build();
    }

}