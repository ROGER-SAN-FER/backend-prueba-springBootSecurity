package com.prueba.springbootsecurity.features.audit.handler;

import com.prueba.springbootsecurity.features.audit.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuditAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final AuditService audit;

    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res,
                         org.springframework.security.core.AuthenticationException ex) throws IOException {
        String user = currentUser();
        audit.record("AUTH_REQUIRED", user, "FAIL", ex.getClass().getSimpleName());
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private String currentUser() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a != null ? a.getName() : "anonymous";
    }
}
