package com.prueba.springbootsecurity.test;

import com.prueba.springbootsecurity.features.auth.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@AutoConfigureMockMvc // addFilters=true por defecto: activa SecurityFilterChain
@ActiveProfiles("test")
class ApiSecurityTests {

    @Autowired
    MockMvc mvc;

    @MockBean
    JwtService jwtService;

    // Si quieres medir 401/403 exactos en /api/** sin pasar por tu auditoría
    // no necesitas más configuración aquí.

    // Endpoints públicos vs protegidos
    @Test
    void public_endpoint_is_accessible() throws Exception {
        mvc.perform(get("/api/public/ping"))
                .andExpect(status().isOk());
    }

    @Test
    void protected_endpoint_without_token_is_401() throws Exception {
        mvc.perform(get("/api/reports/user"))
                .andExpect(status().isUnauthorized()); // 401 -> AuthenticationEntryPoint
    }

    // Autorización por roles (403)
    //a) Con user() (bypass de tu filtro JWT):
    @Test
    void admin_endpoint_as_user_is_403() throws Exception {
        mvc.perform(get("/api/admin/only").with(user("bob").roles("USER")))
                .andExpect(status().isForbidden()); // 403 -> AccessDeniedHandler
    }

    //b) Con Bearer + tu filtro (mockeando JwtService):
    @MockBean
    UserDetailsService uds;
    @Test
    void admin_endpoint_with_bearer_but_no_role_is_403() throws Exception {
        // Prepara mocks para que tu JwtAuthenticationFilter “autentique”
        when(jwtService.extractUsername("valid.token")).thenReturn("bob");
        when(jwtService.isTokenValid("valid.token", "bob")).thenReturn(true);
        var user = User.withUsername("bob").password("x").roles("USER").build();
        when(uds.loadUserByUsername("bob")).thenReturn(user);
        mvc.perform(get("/api/admin/only")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid.token"))
                .andExpect(status().isForbidden());
    }

    // Caso positivo (200) con rol correcto
    @Test
    void user_endpoint_with_role_user_is_200() throws Exception {
        mvc.perform(get("/api/reports/user").with(user("alice").roles("USER")))
                .andExpect(status().isOk());
    }




}
