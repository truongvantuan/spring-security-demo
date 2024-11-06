package com.company.springsecuritydemo.configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.authorizeHttpRequests(requestMatcherRegistry -> {
                    requestMatcherRegistry.requestMatchers("/home").permitAll();
                    requestMatcherRegistry.anyRequest().authenticated();
                })
                .formLogin(formLogin -> formLogin.defaultSuccessUrl("/home"))
                .oauth2Login(oauth2Login -> oauth2Login.defaultSuccessUrl("/home"))
                .addFilterBefore(new RobotFilter(), UsernamePasswordAuthenticationFilter.class)
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
