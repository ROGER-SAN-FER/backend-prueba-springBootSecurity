package com.prueba.springbootsecurity.controller;

import com.prueba.springbootsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {

    public final UserService userService;

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

    // Borrar un usuario
    @DeleteMapping("/{id}")
    public String deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return "Eliminado el usuario " + id;
    }
}
