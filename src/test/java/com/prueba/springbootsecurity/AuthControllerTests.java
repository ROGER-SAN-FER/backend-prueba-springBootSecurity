package com.prueba.springbootsecurity.test;

import com.prueba.springbootsecurity.features.audit.service.AuditService;
import com.prueba.springbootsecurity.features.auth.service.JwtService;
import com.prueba.springbootsecurity.features.auth.service.RefreshTokenService;
import com.prueba.springbootsecurity.features.identity.domain.UserEntity;
import com.prueba.springbootsecurity.features.identity.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTests {
    @Autowired
    MockMvc mvc;

    @MockBean
    AuthenticationManager authManager;

    @MockBean
    AuditService audit;

    @MockBean
    JwtService jwt;

    @MockBean
    UserDetailsService uds;

    @MockBean
    UserRepository userRepo;

    @MockBean
    RefreshTokenService refreshSrv;

    //D) Pruebas de login/refresh/logout (controlador + auditoría)
    //Login KO → 401 y LOGIN_FAILURE
    @Test
    void login_bad_credentials_is_401_and_audited() throws Exception {
        when(authManager.authenticate(any())).thenThrow(new BadCredentialsException("x"));

        mvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content("""
                                {"username":"admin2","password":"wrong"}
                                """))
                .andExpect(status().isUnauthorized());

        verify(audit).record(eq("LOGIN_FAILURE"), eq("admin2"), eq("FAIL"), eq("BadCredentialsException"));
    }


    //Refresh OK → 200 y REFRESH_SUCCESS
    @Test
    void refresh_ok_is_200_and_rotates_and_audits() throws Exception {
        when(jwt.extractUsername("rt1")).thenReturn("alice");
        when(jwt.isTokenValid("rt1", "alice")).thenReturn(true);
        when(refreshSrv.isValid("rt1")).thenReturn(true);

        var ud = User.withUsername("alice").password("x").roles("USER").build();
        when(uds.loadUserByUsername("alice")).thenReturn(ud);

        var userEntity = new UserEntity();
        userEntity.setUsername("alice");
        when(userRepo.findByUsername("alice")).thenReturn(java.util.Optional.of(userEntity));

        when(jwt.generateAccessToken(eq("alice"), anyMap())).thenReturn("accessNew");
        when(jwt.generateRefreshToken("alice")).thenReturn("rt2");
        when(jwt.extractExpiration("rt2")).thenReturn(new java.util.Date(System.currentTimeMillis() + 100000));

        mvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("""
                                {"refreshToken":"rt1"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("accessNew"))
                .andExpect(jsonPath("$.refreshToken").value("rt2"));

        verify(refreshSrv).revoke("rt1");
        verify(refreshSrv).save(eq(userEntity), eq("rt2"), any());
        verify(audit).record("REFRESH_SUCCESS", "alice", "OK", "rotated");
    }

    //Logout sin body → 400 (gracias a DTO + @Valid)
    @Test
    void logout_without_body_is_400() throws Exception {
        mvc.perform(post("/api/auth/logout").contentType("application/json"))
                .andExpect(status().isBadRequest());
    }


}
