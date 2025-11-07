package org.example.securityservicee.configuration;


import org.example.securityservicee.Entities.AppUser;
import org.example.securityservicee.Entities.Role;
import org.example.securityservicee.Repository.AppUserRepository;
import org.example.securityservicee.Repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner init(RoleRepository roleRepo, AppUserRepository userRepo, PasswordEncoder passwordEncoder) {
        return args -> initialize(roleRepo, userRepo, passwordEncoder);
    }

    @Transactional
    public void initialize(RoleRepository roleRepo, AppUserRepository userRepo, PasswordEncoder passwordEncoder) {
        Role roleUser = roleRepo.findByName("USER").orElseGet(() -> roleRepo.save(new Role("USER")));
        Role roleAdmin = roleRepo.findByName("ADMIN").orElseGet(() -> roleRepo.save(new Role("ADMIN")));

        if (!userRepo.existsByUsername("user1")) {
            AppUser u = new AppUser("user1", passwordEncoder.encode("1234"), true);
            u.setRoles(new HashSet<>());
            u.getRoles().add(roleUser);
            userRepo.save(u);
        }

        if (!userRepo.existsByUsername("marwa")) {
            AppUser a = new AppUser("marwa", passwordEncoder.encode("2003"), true);
            a.setRoles(new HashSet<>());
            a.getRoles().add(roleUser);
            a.getRoles().add(roleAdmin);
            userRepo.save(a);
        }
    }
}
