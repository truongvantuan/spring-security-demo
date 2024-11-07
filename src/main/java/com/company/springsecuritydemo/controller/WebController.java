package com.company.springsecuritydemo.controller;


import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class WebController {

    @GetMapping({"/home", "/"})
    public String home() {
        return "Hello World";
    }

    @GetMapping("/private")
    public String privatePage() {
        return "Private Page";
    }

    @GetMapping("/id")
    public String authenticationId(Authentication authentication) {
        return getId(authentication);
    }

    private static String getId(Authentication authentication) {
        return Optional.of(authentication.getPrincipal())
                .filter(OidcUser.class::isInstance)
                .map(OidcUser.class::cast)
                .map(OidcUser::getEmail)
                .orElseGet(authentication::getName);
    }
}
