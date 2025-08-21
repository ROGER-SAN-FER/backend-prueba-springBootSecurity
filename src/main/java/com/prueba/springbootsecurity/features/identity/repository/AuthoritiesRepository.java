package com.prueba.springbootsecurity.features.identity.repository;

import com.prueba.springbootsecurity.features.identity.domain.AuthoritiesEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthoritiesRepository extends JpaRepository<AuthoritiesEntity, Long> {
    Optional<AuthoritiesEntity> findByName(String name);
}
