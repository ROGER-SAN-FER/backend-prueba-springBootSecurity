package com.prueba.springbootsecurity.security.oauth2;

import com.prueba.springbootsecurity.security.auth.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.*;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        var token = (OAuth2AuthenticationToken) authentication;
        var principal = token.getPrincipal();

        // Normalizamos identidad
        String provider = token.getAuthorizedClientRegistrationId(); // "google" | "facebook"
        String username;
        String email = null;
        Map<String,Object> claims = new HashMap<>();
        claims.put("provider", provider);

        if (principal instanceof OidcUser oidc) {              // Google (OIDC)
            username = oidc.getSubject();                        // sub
            email = oidc.getEmail();
            claims.put("name", oidc.getFullName());
            claims.put("email", email);
        } else {                                               // Facebook (OAuth2)
            OAuth2User ou = (OAuth2User) principal;
            // Facebook puede no devolver email si el usuario no lo permite
            email = (String) ou.getAttributes().get("email");
            username = email != null ? email : (String) ou.getAttributes().get("id");
            claims.putAll(ou.getAttributes());
        }

        // Authorities del login social (normalmente ROLE_USER)
        var authorities = principal.getAuthorities().stream().map(a -> a.getAuthority()).toList();
        claims.put("roles", authorities);

        // Emitimos *tu* JWT de acceso y refresh
        String access = jwtService.generateAccessToken(username, claims);
        String refresh = jwtService.generateRefreshToken(username);

        // Devolvemos JSON directo (alternativa: redirigir a tu frontend con tokens en fragment/hash)
        response.setContentType("application/json");
        response.getWriter().write("""
        { "accessToken": "%s", "refreshToken": "%s" }
        """.formatted(access, refresh));
    }
}
