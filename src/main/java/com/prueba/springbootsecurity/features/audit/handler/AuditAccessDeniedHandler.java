package com.prueba.springbootsecurity.features.audit.handler;

import com.prueba.springbootsecurity.features.audit.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuditAccessDeniedHandler implements AccessDeniedHandler {

    private final AuditService audit;

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res, AccessDeniedException ex) throws IOException {
        String user = currentUser();
        audit.record("ACCESS_DENIED", user, "FAIL", ex.getMessage());
        res.sendError(HttpServletResponse.SC_FORBIDDEN);
    }

    private String currentUser() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a != null ? a.getName() : "anonymous";
    }
}

