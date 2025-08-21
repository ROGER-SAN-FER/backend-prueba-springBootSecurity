package com.prueba.springbootsecurity.reporting.controller;

import com.prueba.springbootsecurity.features.identity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {

    public final UserService userService;

    @GetMapping("/secure")
    String secure(Authentication auth){
        return "Hello API, user=" + auth.getName();
    }

    @GetMapping("/public/ping")
    public String publicPing() {
        return "pong público (API)";
    }

    @CrossOrigin(
            origins = {"http://localhost:3000"},
            methods = {RequestMethod.GET, RequestMethod.POST},
            allowedHeaders = {"Authorization","Content-Type"}
    )
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
