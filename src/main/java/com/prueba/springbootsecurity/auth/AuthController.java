package com.prueba.springbootsecurity.auth;

import com.prueba.springbootsecurity.model.dto.AuthRequest;
import com.prueba.springbootsecurity.model.dto.AuthResponse;
import com.prueba.springbootsecurity.model.entity.UserEntity;
import com.prueba.springbootsecurity.repository.UserRepository;
import com.prueba.springbootsecurity.service.JwtService;
import com.prueba.springbootsecurity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
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
    private final UserRepository userRepo; // asegúrate que la tienes

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest req) {
        // Autentica credenciales (lanza excepción si fallan)
        var authToken = new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword());
        authManager.authenticate(authToken);

        // Carga el usuario (para claims/roles)
        UserDetails user = userDetailsService.loadUserByUsername(req.getUsername());

        // Incluye roles/authorities como claim "roles"
        var extraClaims = Map.<String,Object>of(
                "roles", user.getAuthorities().stream().map(a -> a.getAuthority()).toList()
        );

        String access = jwt.generateAccessToken(user.getUsername(), extraClaims);
        String refresh = jwt.generateRefreshToken(user.getUsername());

        // ++ guardamos hash en BD
        UserEntity userEntity = userRepo.findByUsername(req.getUsername()).orElseThrow();
        refreshTokenService.save(userEntity, refresh, jwt.extractExpiration(refresh).toInstant());

        return ResponseEntity.ok(new AuthResponse(access, refresh));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        String username = jwt.extractUsername(refreshToken);
        UserDetails user = userDetailsService.loadUserByUsername(username);

        // validación en BD además de validar firma/exp
        if (!jwt.isTokenValid(refreshToken, username) || !refreshTokenService.isValid(refreshToken)) {
            throw new BadCredentialsException("Refresh token inválido o expirado");
        }

        var extraClaims = Map.<String,Object>of(
                "roles", user.getAuthorities().stream().map(a -> a.getAuthority()).toList()
        );
        String newAccess = jwt.generateAccessToken(username, extraClaims);
        String newRefresh = jwt.generateRefreshToken(username); // rotación simple

        // revocamos el viejo y guardamos el nuevo
        UserEntity userEntity = userRepo.findByUsername(username).orElseThrow();
        refreshTokenService.revoke(refreshToken);
        refreshTokenService.save(userEntity, newRefresh, jwt.extractExpiration(newRefresh).toInstant());

        return ResponseEntity.ok(new AuthResponse(newAccess, newRefresh));
    }

    // ++ nuevo endpoint logout
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody Map<String,String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken != null) {
            refreshTokenService.revoke(refreshToken);
        }
        return ResponseEntity.ok().build();
    }
}
