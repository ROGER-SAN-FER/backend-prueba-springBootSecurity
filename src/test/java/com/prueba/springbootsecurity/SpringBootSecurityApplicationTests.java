package com.prueba.springbootsecurity;

import com.prueba.springbootsecurity.security.auth.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class SpringBootSecurityApplicationTests {

    @MockBean
    JwtService jwtService;

    @Test
    void contextLoads() {
    }

}
