package com.prueba.springbootsecurity.config;

import com.prueba.springbootsecurity.model.entity.AuthoritiesEntity;
import com.prueba.springbootsecurity.model.entity.RoleEntity;
import com.prueba.springbootsecurity.model.entity.UserEntity;
import com.prueba.springbootsecurity.repository.AuthoritiesRepository;
import com.prueba.springbootsecurity.repository.RoleRepository;
import com.prueba.springbootsecurity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.Set;
import static com.prueba.springbootsecurity.model.entity.RoleEnum.ADMIN;
import static com.prueba.springbootsecurity.model.entity.RoleEnum.USER;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initData(AuthoritiesRepository authRepo,
                               RoleRepository roleRepo,
                               UserRepository userRepo,
                               PasswordEncoder encoder) {
        return args -> {
            // Permisos
            var reportRead  = authRepo.findByName("REPORT_READ").orElseGet(() -> authRepo.save(new AuthoritiesEntity("REPORT_READ")));
            var reportWrite = authRepo.findByName("REPORT_WRITE").orElseGet(() -> authRepo.save(new AuthoritiesEntity("REPORT_WRITE")));

            // Roles
            var userRole = roleRepo.findByName("USER").orElseGet(() -> {
                var newRol = new RoleEntity(USER);
                newRol.setAuthoritiesList(Set.of(reportRead));
                return roleRepo.save(newRol);
            });

            var adminRole = roleRepo.findByName("ADMIN").orElseGet(() -> {
                var newRol = new RoleEntity(ADMIN);
                newRol.setAuthoritiesList(Set.of(reportRead, reportWrite));
                return roleRepo.save(newRol);
            });

            // Usuarios
            if (userRepo.findByUsername("user").isEmpty()) {
                var newUser = new UserEntity ("user", encoder.encode("user123"));
                newUser.setRolesList(Set.of(userRole));
                userRepo.save(newUser);
            }
            if (userRepo.findByUsername("admin").isEmpty()) {
                var newUser = new UserEntity("admin", encoder.encode("admin123"));
                newUser.setRolesList(Set.of(adminRole));
                userRepo.save(newUser);
            }
        };
    }
}
