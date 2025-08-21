package com.prueba.springbootsecurity.audit;

import com.prueba.springbootsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
public class LoginThrottleService {

    private final UserRepository users;

    // Ajusta a tu política
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 15;

    public void preCheck(String username) {
        users.findByUsername(username).ifPresent(u -> {
            if (u.getLockUntil() != null && u.getLockUntil().isAfter(Instant.now())) {
                throw new LockedException("Cuenta bloqueada hasta: " + u.getLockUntil());
            }
        });
    }

    @Transactional
    public void onFailure(String username) {
        users.findByUsername(username).ifPresent(u -> {
            int fails = u.getFailedAttempts() + 1;
            u.setFailedAttempts(fails);
            if (fails >= MAX_ATTEMPTS) {
                u.setLockUntil(Instant.now().plus(LOCK_MINUTES, ChronoUnit.MINUTES));
                u.setFailedAttempts(0); // opcional: resetea al bloquear
            }
        });
    }

    @Transactional
    public void onSuccess(String username) {
        users.findByUsername(username).ifPresent(u -> {
            u.setFailedAttempts(0);
            u.setLockUntil(null);
        });
    }
}
