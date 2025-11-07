package org.example.securityservicee.service;


import org.example.securityservicee.Entities.AppUser;
import org.example.securityservicee.Repository.AppUserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final AppUserRepository repository;

    public JpaUserDetailsService(AppUserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = repository.findByUsername(username);
        if (appUser == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        var authorities = appUser.getRoles().stream()
                .map(role -> {
                    // Spring Security expects "ROLE_" prefix when using hasRole(...)
                    String roleName = role.getName();
                    if (!roleName.startsWith("ROLE_")) {
                        roleName = "ROLE_" + roleName;
                    }
                    return new SimpleGrantedAuthority(roleName);
                })
                .collect(Collectors.toSet());

        return org.springframework.security.core.userdetails.User
                .withUsername(appUser.getUsername())
                .password(appUser.getPassword())
                .authorities(authorities)
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(!appUser.isEnabled())
                .build();
    }
}
