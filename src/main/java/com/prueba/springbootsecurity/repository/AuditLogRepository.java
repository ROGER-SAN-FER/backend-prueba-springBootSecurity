package com.prueba.springbootsecurity.repository;

import com.prueba.springbootsecurity.model.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {}
