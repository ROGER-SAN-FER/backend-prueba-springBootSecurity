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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;



import static org.mockito.Mockito.when;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class JwtFilterTests {
    @Autowired
    MockMvc mvc;

    @MockBean
    JwtService jwtService;

    @MockBean
    UserDetailsService uds;

    @Test
    void valid_bearer_token_authenticates_request() throws Exception {
        when(jwtService.extractUsername("abc")).thenReturn("roger");
        when(jwtService.isTokenValid("abc", "roger")).thenReturn(true);
        var user = User.withUsername("roger").password("x").roles("USER").build();
        when(uds.loadUserByUsername("roger")).thenReturn(user);

        mvc.perform(get("/api/reports/user").header(HttpHeaders.AUTHORIZATION, "Bearer abc"))
                .andExpect(status().isOk()); // autenticado -> pasa regla USER/ADMIN
    }

    @Test
    void invalid_bearer_token_results_in_401() throws Exception {
        when(jwtService.extractUsername("bad")).thenThrow(new RuntimeException("bad token"));

        mvc.perform(get("/api/reports/user").header(HttpHeaders.AUTHORIZATION, "Bearer bad"))
                .andExpect(status().isUnauthorized()); // EntryPoint
    }
}
