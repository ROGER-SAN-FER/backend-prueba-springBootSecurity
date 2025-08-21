package com.prueba.springbootsecurity.features.auth.model.entity;

import com.prueba.springbootsecurity.features.identity.domain.UserEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(nullable = false, unique = true, length = 128)
    private String tokenHash; // hash SHA-256 del refresh

    @Column(nullable = false)
    private Instant expiresAt;

    @Column
    private Instant revokedAt; // null si sigue válido
}
