package com.prueba.springbootsecurity.features.identity.repository;

import com.prueba.springbootsecurity.features.identity.domain.RoleEntity;
import com.prueba.springbootsecurity.features.identity.domain.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    Optional<RoleEntity> findByRoleEnum(RoleEnum roleEnum);
}
