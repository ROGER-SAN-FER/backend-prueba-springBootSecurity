package com.prueba.springbootsecurity.test;

import com.prueba.springbootsecurity.features.auth.service.JwtService;
import com.prueba.springbootsecurity.reporting.service.ReportService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
@ActiveProfiles("test")
public class MethodSecurityTests {

    //E) Pruebas de metodo (si usas @PreAuthorize)
    @Autowired
    ReportService reports; // imaginemos @PreAuthorize("hasRole('ADMIN')")

    // ++ evita que Spring cree el JwtService real (que requiere PublicKey/PrivateKey)
    @MockBean
    JwtService jwtService;

    // ++ el filtro también depende de esto; mockéalo para simplificar
    @MockBean
    UserDetailsService uds;

    @Test
    @WithMockUser(username="alice", roles={"USER"})
    void user_cannot_call_admin_method() {
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> reports.generateSensitiveReport());
    }

    @Test
    @WithMockUser(username="admin", roles={"ADMIN"})
    void admin_can_call_admin_method() {
        assertDoesNotThrow(() -> reports.generateSensitiveReport());
    }
}
