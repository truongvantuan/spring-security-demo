package com.company.springsecuritydemo.configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultFilterChain(HttpSecurity httpSecurity) throws Exception {

        var robotLoginConfigurer = new RobotLoginConfigurer()
                .password("ping-pong")
                .password("pong-ping");

        return httpSecurity.authorizeHttpRequests(requestMatcherRegistry -> {
                    requestMatcherRegistry.requestMatchers("/home").permitAll();
                    requestMatcherRegistry.anyRequest().authenticated();
                })
                .formLogin(formLogin -> formLogin.defaultSuccessUrl("/home"))
                .oauth2Login(oauth2Configurer -> {
                    oauth2Configurer.addObjectPostProcessor(new ObjectPostProcessor<AuthenticationProvider>() {
                        @Override
                        public <O extends AuthenticationProvider> O postProcess(O object) {
                            return (O) new RateLimitedAuthenticationProvider(object);
                        }
                    });
                })
                .with(robotLoginConfigurer, withDefaults())
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
