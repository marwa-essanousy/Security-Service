package org.example.securityservicee.Repository;


import org.example.securityservicee.Entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, String> {
    AppUser findByUsername(String username);
    boolean existsByUsername(String username);
}
