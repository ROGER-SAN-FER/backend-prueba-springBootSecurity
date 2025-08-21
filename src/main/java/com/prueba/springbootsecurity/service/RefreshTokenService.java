package com.prueba.springbootsecurity.service;

import com.prueba.springbootsecurity.model.entity.RefreshTokenEntity;
import com.prueba.springbootsecurity.model.entity.UserEntity;
import com.prueba.springbootsecurity.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repo;

    public RefreshTokenEntity save(UserEntity user, String rawRefresh, Instant expiresAt) {
        String hash = sha256(rawRefresh);
        RefreshTokenEntity entity = RefreshTokenEntity.builder()
                .user(user)
                .tokenHash(hash)
                .expiresAt(expiresAt)
                .build();
        return repo.save(entity);
    }

    public boolean isValid(String rawRefresh) {
        return repo.findByTokenHash(sha256(rawRefresh))
                .filter(rt -> rt.getRevokedAt() == null && rt.getExpiresAt().isAfter(Instant.now()))
                .isPresent();
    }

    public void revoke(String rawRefresh) {
        repo.findByTokenHash(sha256(rawRefresh)).ifPresent(rt -> {
            rt.setRevokedAt(Instant.now());
            repo.save(rt);
        });
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
