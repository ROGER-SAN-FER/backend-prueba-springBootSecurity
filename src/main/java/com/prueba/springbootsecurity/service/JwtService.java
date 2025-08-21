package com.prueba.springbootsecurity.service;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final String issuer;
    private final long accessSeconds;
    private final long refreshSeconds;

    public JwtService(
            PublicKey jwtPublicKey,
            PrivateKey jwtPrivateKey,
            @Value("${security.jwt.issuer}") String issuer,
            @Value("${security.jwt.access.minutes}") long accessMinutes,
            @Value("${security.jwt.refresh.days}") long refreshDays
    ) {
        this.publicKey = jwtPublicKey;
        this.privateKey = jwtPrivateKey;
        this.issuer = issuer;
        this.accessSeconds = accessMinutes * 60;
        this.refreshSeconds = refreshDays * 24 * 3600;
    }

    public String generateAccessToken(String username, Map<String, Object> extraClaims) {
        Instant now = Instant.now();
        return Jwts.builder()
                .addClaims(extraClaims == null ? Map.of() : extraClaims)
                .setIssuer(issuer)
                .setSubject(username)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(accessSeconds)))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public String generateRefreshToken(String username) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setIssuer(issuer)
                .setSubject(username)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(refreshSeconds)))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public boolean isTokenValid(String token, String username) {
        try {
            String sub = extractUsername(token);
            return username.equals(sub) && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey) // usar verifyWith(...) si es jjwt 0.12+
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsResolver.apply(claims);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Instant extractExpirationInstant(String token) {
        return extractExpiration(token).toInstant();
    }
}

