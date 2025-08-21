package com.prueba.springbootsecurity.repository;

import com.prueba.springbootsecurity.model.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);
    void deleteByTokenHash(String tokenHash);
}
