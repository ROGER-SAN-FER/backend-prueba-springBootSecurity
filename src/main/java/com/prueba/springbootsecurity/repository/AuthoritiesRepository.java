package com.prueba.springbootsecurity.repository;

import com.prueba.springbootsecurity.model.entity.AuthoritiesEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthoritiesRepository extends JpaRepository<AuthoritiesEntity, Long> {
    Optional<AuthoritiesEntity> findByName(String name);
}
