package com.prueba.springbootsecurity.security.auth;

import com.prueba.springbootsecurity.model.dto.AuthRequest;
import com.prueba.springbootsecurity.model.dto.AuthResponse;
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

        if (!jwt.isTokenValid(refreshToken, username)) {
            throw new BadCredentialsException("Refresh token inválido o expirado");
        }

        var extraClaims = Map.<String,Object>of(
                "roles", user.getAuthorities().stream().map(a -> a.getAuthority()).toList()
        );
        String newAccess = jwt.generateAccessToken(username, extraClaims);
        String newRefresh = jwt.generateRefreshToken(username); // rotación simple

        return ResponseEntity.ok(new AuthResponse(newAccess, newRefresh));
    }
}
