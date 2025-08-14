package com.prueba.springbootsecurity.model.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
@Builder
@NoArgsConstructor
@RequiredArgsConstructor
@Entity
@Table(name = "roles")
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NonNull
    @Enumerated(EnumType.STRING)
    @Column(name = "role_name", unique = true, nullable = false, length = 64)
    private RoleEnum roleEnum;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(
            name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<AuthoritiesEntity> authoritiesList = new HashSet<>();
}
