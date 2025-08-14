package com.prueba.springbootsecurity.repository;

import com.prueba.springbootsecurity.model.entity.RoleEntity;
import com.prueba.springbootsecurity.model.entity.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    Optional<RoleEntity> findByRoleEnum(RoleEnum roleEnum);
}
