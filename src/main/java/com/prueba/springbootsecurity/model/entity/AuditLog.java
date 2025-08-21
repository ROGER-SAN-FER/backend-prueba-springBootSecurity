package com.prueba.springbootsecurity.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "audit_log", indexes = {
        @Index(name="ix_audit_when", columnList="occurredAt"),
        @Index(name="ix_audit_principal", columnList="principal"),
        @Index(name="ix_audit_type", columnList="type")
})
@Getter @Setter
public class AuditLog {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String type;          // LOGIN_SUCCESS, LOGIN_FAILURE, REFRESH_SUCCESS, ACCESS_DENIED, etc.

    @Column(nullable = true, length = 128)
    private String principal;     // username/sub; "anonymous" si no hay

    @Column(nullable = false)
    private Instant occurredAt = Instant.now();

    // contexto
    @Column(length = 64)  private String ip;
    @Column(length = 256) private String userAgent;
    @Column(length = 8)   private String method;
    @Column(length = 256) private String path;
    @Column(length = 16)  private String outcome; // OK / FAIL
    @Column(length = 512) private String detail;  // motivo de fallo / breve detalle
}
