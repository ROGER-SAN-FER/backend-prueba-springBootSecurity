package com.prueba.springbootsecurity.features.identity.domain;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
@RequiredArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NonNull
    @Column(unique = true, nullable = false, length=64)
    private String username;

    @NonNull
    @Column(nullable=false)
    private String password;

    private boolean enabled;

    @Column(name = "account_no_expired")
    private boolean accountNonExpired;

    @Column(name = "account_no_locked")
    private boolean accountNonLocked;

    @Column(name = "credentials_no_expired")
    private boolean credentialsNonExpired;

    // Para audit
    @Column(name = "failed_attempts", /*columnDefinition = "integer default 0"*/nullable = false)
    private int failedAttempts = 0;

    // Para audit
    @Column(name = "lock_until") // null si no está bloqueado
    private java.time.Instant lockUntil;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<RoleEntity> rolesList = new HashSet<>();
}
