package com.prueba.springbootsecurity.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class ReportService {

    @PreAuthorize("hasRole('ADMIN')")
    public String generateSensitiveReport() {
        return "Reporte sensible generado solo para ADMIN.";
    }

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public String generateUserReport() {
        return "Reporte de usuario generado para USER y ADMIN.";
    }
}
