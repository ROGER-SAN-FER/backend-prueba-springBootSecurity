package com.prueba.springbootsecurity.features.identity.service;

import com.prueba.springbootsecurity.features.identity.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepo;

    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public void deleteUser(Long userId) {
        var u = userRepo.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("No existe user " + userId));

        // Rompe las relaciones en el lado propietario (donde está @JoinTable)
        u.getRolesList().clear();
        userRepo.save(u);     // borra filas del join table
        userRepo.delete(u);   // ahora sí, borra al usuario
    }
}
