package com.codeconfessions.springsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.codeconfessions.springsecurity.model.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDAOService implements ApplicationUserDAO {

    private PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDAOService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter( user -> user.getUsername().equals(username))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        "annasmith",
                        passwordEncoder.encode("password"),
                        STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(
                        "linda",
                        passwordEncoder.encode("password123"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(
                        "tom",
                        passwordEncoder.encode("password123"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true)
        );

        return applicationUsers;
    }
}
