package org.example.securityservicee.Entities;


import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "role")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // stocke le nom sans ROLE_ ou avec, selon préférence. Nous utiliserons "ADMIN" / "USER".
    @Column(unique = true, nullable = false)
    private String name;

    @ManyToMany(mappedBy = "roles")
    private Set<AppUser> users = new HashSet<>();

    public Role() {}

    public Role(String name) { this.name = name; }

    // getters & setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public Set<AppUser> getUsers() { return users; }
    public void setUsers(Set<AppUser> users) { this.users = users; }
}
