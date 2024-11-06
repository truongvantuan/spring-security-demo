package com.company.springsecuritydemo.configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultFilterChain(HttpSecurity httpSecurity) throws Exception {

        ProviderManager providerManager = new ProviderManager(
                new RobotAuthenticationProvider(List.of("ping-pong", "pong-ping"))
        );

        var robotLoginConfigurer = new RobotLoginConfigurer()
                .password("ping-pong")
                .password("pong-ping");

        return httpSecurity.authorizeHttpRequests(requestMatcherRegistry -> {
                    requestMatcherRegistry.requestMatchers("/home").permitAll();
                    requestMatcherRegistry.anyRequest().authenticated();
                })
                .formLogin(formLogin -> formLogin.defaultSuccessUrl("/home"))
                .oauth2Login(oauth2Login -> oauth2Login.defaultSuccessUrl("/home"))
                .with(robotLoginConfigurer, withDefaults())
//                .addFilterBefore(new RobotFilter(providerManager), UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(new DanielAuthenticationProvider())
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("user")
                        .password("{noop}0000")
                        .authorities("ROLE_user")
                        .build()
        );
    }
}
