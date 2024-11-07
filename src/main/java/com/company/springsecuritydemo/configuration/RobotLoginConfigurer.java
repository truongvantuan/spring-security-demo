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
    public void init(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authenticationProvider(new RobotAuthenticationProvider(passwords));
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        var authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        httpSecurity.addFilterBefore(new RobotFilter(authenticationManager), AuthorizationFilter.class);
    }

    public RobotLoginConfigurer password(String password) {
        passwords.add(password);
        return this;
    }
}
