package com.prueba.springbootsecurity.service;

import com.prueba.springbootsecurity.model.entity.AuditLog;
import com.prueba.springbootsecurity.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository repo;

    public void record(String type, String principal, String outcome, String detail) {
        HttpServletRequest req = currentRequest();

        AuditLog log = new AuditLog();
        log.setType(type);
        log.setPrincipal(principal);
        log.setOutcome(outcome);
        log.setDetail(safe(detail));
        log.setOccurredAt(Instant.now());

        if (req != null) {
            log.setIp(extractIp(req));
            log.setUserAgent(req.getHeader("User-Agent"));
            log.setMethod(req.getMethod());
            log.setPath(req.getRequestURI());
        }
        repo.save(log);
    }

    private HttpServletRequest currentRequest() {
        var attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest() : null;
    }

    private String extractIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isBlank()) ? xff.split(",")[0].trim() : req.getRemoteAddr();
    }

    private String safe(String s) {
        if (s == null) return null;
        return s.length() > 500 ? s.substring(0, 500) : s;
    }
}
