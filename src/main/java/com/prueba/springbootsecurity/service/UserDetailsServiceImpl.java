package com.prueba.springbootsecurity.service;

import com.prueba.springbootsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Stream;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

        var permissions = Stream.concat(
                        user.getRolesList().stream().map(rol -> new SimpleGrantedAuthority("ROLE_" + rol.getRoleEnum())),
                        user.getRolesList().stream().flatMap(rol -> rol.getPermissionsList().stream())
                                .map(a -> new SimpleGrantedAuthority(a.getName()))
                )
                .distinct()
                .toList();

        return User.withUsername(user.getUsername())
                .password(user.getPassword())
                .authorities(permissions)
                .accountExpired(!user.isAccountNonExpired())
                .accountLocked(!user.isAccountNonLocked())
                .credentialsExpired(!user.isCredentialsNonExpired())
                .disabled(!user.isEnabled())
                .build();
    }
}
