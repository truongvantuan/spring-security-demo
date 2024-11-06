package com.company.springsecuritydemo.configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.util.ArrayList;
import java.util.List;

public class RobotLoginConfigurer extends AbstractHttpConfigurer<RobotLoginConfigurer, HttpSecurity> {

    private final List<String> passwords = new ArrayList<>();

    @Override
    public void init(HttpSecurity builder) throws Exception {
        builder.authenticationProvider(new RobotAuthenticationProvider(passwords));
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        var authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        builder.addFilterBefore(new RobotFilter(authenticationManager), AuthorizationFilter.class);
    }

    public RobotLoginConfigurer password(String password) {
        passwords.add(password);
        return this;
    }
}
