package com.prueba.springbootsecurity.reporting.service;

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

    //Aunque USER y ADMIN tiene permisos de rol por SecurityFilterChain, a nivel de profundidad solo puede
    //acceder el que tiene el permiso authority
    @PreAuthorize("hasAnyAuthority('REPORT_WRITE')")
    public String generateUserReportRead() {
        return "Reporte de usuario generado para USER y ADMIN.";
    }
}
