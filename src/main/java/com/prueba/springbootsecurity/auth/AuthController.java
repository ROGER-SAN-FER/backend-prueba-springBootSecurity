package com.prueba.springbootsecurity.auth;


import com.prueba.springbootsecurity.audit.LoginThrottleService;
import com.prueba.springbootsecurity.model.dto.AuthRequest;
import com.prueba.springbootsecurity.model.dto.AuthResponse;
import com.prueba.springbootsecurity.model.dto.LogoutRequest;
import com.prueba.springbootsecurity.model.entity.UserEntity;
import com.prueba.springbootsecurity.repository.UserRepository;

import com.prueba.springbootsecurity.service.AuditService;
import com.prueba.springbootsecurity.service.JwtService;

import com.prueba.springbootsecurity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwt;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepo;

    private final AuditService audit;
    private final LoginThrottleService throttle;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest req) {
        // Bloqueo por intentos fallidos
        throttle.preCheck(req.getUsername());

        var authToken = new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword());
        try {
            authManager.authenticate(authToken);

            UserDetails user = userDetailsService.loadUserByUsername(req.getUsername());
            var extraClaims = Map.<String,Object>of(
                    "roles", user.getAuthorities().stream().map(a -> a.getAuthority()).toList()
            );

            String access = jwt.generateAccessToken(user.getUsername(), extraClaims);
            String refresh = jwt.generateRefreshToken(user.getUsername());

            UserEntity userEntity = userRepo.findByUsername(req.getUsername()).orElseThrow();
            refreshTokenService.save(userEntity, refresh, jwt.extractExpiration(refresh).toInstant());

            throttle.onSuccess(req.getUsername());
            audit.record("LOGIN_SUCCESS", req.getUsername(), "OK", null);

            return ResponseEntity.ok(new AuthResponse(access, refresh));
        } catch (AuthenticationException ex) {
            throttle.onFailure(req.getUsername());
            audit.record("LOGIN_FAILURE", req.getUsername(), "FAIL", ex.getClass().getSimpleName());
            throw ex; // dejar que tu handler global devuelva 401
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken == null || refreshToken.isBlank()) {
            audit.record("REFRESH_FAILURE", "anonymous", "FAIL", "missing_refresh");
            return ResponseEntity.badRequest().build();
        }
        String username = jwt.extractUsername(refreshToken);
        UserDetails user = userDetailsService.loadUserByUsername(username);

        if (!jwt.isTokenValid(refreshToken, username) || !refreshTokenService.isValid(refreshToken)) {
            audit.record("REFRESH_FAILURE", username, "FAIL", "invalid_or_revoked");
            throw new BadCredentialsException("Refresh token inválido o expirado");
        }

        var extraClaims = Map.<String,Object>of(
                "roles", user.getAuthorities().stream().map(a -> a.getAuthority()).toList()
        );
        String newAccess = jwt.generateAccessToken(username, extraClaims);
        String newRefresh = jwt.generateRefreshToken(username);

        UserEntity userEntity = userRepo.findByUsername(username).orElseThrow();
        refreshTokenService.revoke(refreshToken);
        refreshTokenService.save(userEntity, newRefresh, jwt.extractExpiration(newRefresh).toInstant());

        audit.record("REFRESH_SUCCESS", username, "OK", "rotated");
        return ResponseEntity.ok(new AuthResponse(newAccess, newRefresh));
    }

    @PostMapping(value = "/logout", consumes = "application/json")
    public ResponseEntity<Void> logout(@RequestBody @jakarta.validation.Valid LogoutRequest req) {
        // si falta o está en blanco, Spring lanza 400 automáticamente
        refreshTokenService.revoke(req.refreshToken());
        audit.record("LOGOUT", safeUserFromToken(req.refreshToken()), "OK", null);
        return ResponseEntity.noContent().build(); // 204
    }

    private String safeUserFromToken(String refreshToken) {
        try { return jwt.extractUsername(refreshToken); }
        catch (Exception e) { return "anonymous"; }
    }
}
