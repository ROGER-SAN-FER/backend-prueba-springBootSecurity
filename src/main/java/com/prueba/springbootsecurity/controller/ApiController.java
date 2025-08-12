package com.prueba.springbootsecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/public/ping")
    public String publicPing() {
        return "pong público (API)";
    }

    @GetMapping("/user/me")
    public String userMe(Authentication auth) {
        return "Hola, " + auth.getName() + " con roles " + auth.getAuthorities();
    }

    @GetMapping("/admin/metrics")
    public String adminMetrics() {
        return "Métricas solo ADMIN";
    }
}
