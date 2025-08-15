package com.prueba.springbootsecurity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApiSecurityTest {

    @TestConfiguration
    static class TestRsaKeyConfig {
        @Bean
        PublicKey jwtPublicKey() throws Exception { return testKeyPair().getPublic(); }

        @Bean
        PrivateKey jwtPrivateKey() throws Exception { return testKeyPair().getPrivate(); }

        @Bean
        KeyPair testKeyPair() throws Exception {
            var kpg = java.security.KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        }
    }

    @Autowired
    MockMvc mvc;

    @Test
    void public_ping_is_open() throws Exception {
        mvc.perform(get("/api/public/ping"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username="pepe", roles={"USER"})
    void user_me_returns_auth_info_when_authenticated() throws Exception {
        mvc.perform(get("/api/user/me").accept(MediaType.TEXT_PLAIN))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("pepe")));
    }

    @Test
    @WithMockUser(roles={"USER"})
    void admin_metrics_is_forbidden_for_user() throws Exception {
        mvc.perform(get("/api/admin/metrics"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles={"ADMIN"})
    void admin_metrics_ok_for_admin() throws Exception {
        mvc.perform(get("/api/admin/metrics"))
                .andExpect(status().isOk());
    }

    @Test
    void cors_preflight_allows_frontend_origin() throws Exception {
        mvc.perform(options("/api/user/me")
                        .header("Origin", "http://localhost:4200")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:4200"))
                .andExpect(header().string("Vary", containsString("Origin")));
    }

    @Test
    void cors_preflight_blocks_unlisted_origin() throws Exception {
        mvc.perform(options("/api/user/me")
                        .header("Origin", "http://evil.example.com")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden()); // o 200 sin ACAO, depende de versión/config
    }
}
