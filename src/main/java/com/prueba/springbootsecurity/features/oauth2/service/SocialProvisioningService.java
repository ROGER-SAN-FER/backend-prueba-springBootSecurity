package com.prueba.springbootsecurity.features.oauth2.service;

import com.prueba.springbootsecurity.features.identity.domain.RoleEntity;
import com.prueba.springbootsecurity.features.identity.domain.RoleEnum;
import com.prueba.springbootsecurity.features.identity.domain.UserEntity;

import com.prueba.springbootsecurity.features.identity.repository.RoleRepository;
import com.prueba.springbootsecurity.features.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SocialProvisioningService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder passwordEncoder;

    /**
     * Crea o actualiza un usuario social en la BD.
     * - Usa el email como username si existe; si no, "provider:providerUserId".
     * - Asigna ROLE_USER por defecto si es nuevo.
     */
    @Transactional
    public UserEntity provisionOrUpdate(String provider, String providerUserId, String email, String fullName) {
        // username “estable”: email si hay, si no provider:sub (p.ej. google:1234567890)
        String username = (email != null && !email.isBlank())
                ? email.trim().toLowerCase()
                : (provider + ":" + providerUserId);

        var existing = userRepo.findByUsername(username);
        if (existing.isPresent()) {
            // Si quieres, podrías guardar fullName en tu entidad si tuvieras ese campo
            // (tu UserEntity no lo tiene; lo dejamos así).
            return existing.get();
        }

        // Crear user nuevo
        var user = new UserEntity();
        user.setUsername(username);
        // Password aleatoria (no se usará para login social, pero cumple @NonNull)
        user.setPassword(passwordEncoder.encode("SOCIAL-" + UUID.randomUUID()));
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);

        // Rol por defecto: USER
        RoleEntity defaultRole = roleRepo.findByRoleEnum(RoleEnum.USER)
                .orElseThrow(() -> new IllegalStateException("Debe existir el rol USER en la BD"));
        user.getRolesList().add(defaultRole);

        return userRepo.save(user);
    }
}
