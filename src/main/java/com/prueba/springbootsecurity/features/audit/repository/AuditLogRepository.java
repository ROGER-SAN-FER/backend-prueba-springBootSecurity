package com.prueba.springbootsecurity.features.audit.repository;

import com.prueba.springbootsecurity.features.audit.domain.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {}
