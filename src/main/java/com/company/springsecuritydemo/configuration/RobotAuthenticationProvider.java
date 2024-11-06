package com.company.springsecuritydemo.configuration;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

public class RobotAuthenticationProvider implements AuthenticationProvider {

    private final List<String> listPassword;

    public RobotAuthenticationProvider(List<String> listPassword) {
        this.listPassword = listPassword;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RobotAuthentication authRequest = (RobotAuthentication) authentication;
        String password = authRequest.getPassword();
        if (!listPassword.contains(password)) {
            throw new BadCredentialsException("Bad credentials");
        }
        return RobotAuthentication.authenticated();
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return RobotAuthentication.class.isAssignableFrom(authentication);
    }
}
