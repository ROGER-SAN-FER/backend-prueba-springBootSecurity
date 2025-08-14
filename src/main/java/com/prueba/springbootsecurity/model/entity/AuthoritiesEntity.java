package com.prueba.springbootsecurity.model.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Setter
@Getter
@Builder
@RequiredArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "authorities")
public class AuthoritiesEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NonNull
    @Column(name = "authority_name", unique = true, nullable = false, length = 64)
    private String name;
}
