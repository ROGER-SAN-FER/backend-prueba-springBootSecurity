package com.prueba.springbootsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class PublicController {

    @GetMapping("/")
    @ResponseBody
    public String landing() {
        return "Bienvenido (público). Ve a /login para iniciar sesión o /public/hello";
    }

    @GetMapping("/public/hello")
    @ResponseBody
    public String hello() {
        return "Hola mundo público (web)";
    }

    @GetMapping("/public/goodbye")
    @ResponseBody
    public String goodbye() {
        return "Sesión cerrada. ¡Hasta pronto!";
    }

    @GetMapping("/login")
    public String loginPage() {
        // Para no usar plantillas, reenviamos a info textual
        return "forward:/public/login-info";
    }

    @GetMapping("/public/login-info")
    @ResponseBody
    public String loginInfo() {
        return "Página de login (demo). Puedes usar la UI por defecto de Spring Security o POSTear credenciales.";
    }

    @GetMapping("/home")
    @ResponseBody
    public String home() {
        return "Home autenticado (web).";
    }
}
