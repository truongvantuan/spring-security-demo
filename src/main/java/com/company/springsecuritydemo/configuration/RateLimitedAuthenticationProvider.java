package com.company.springsecuritydemo.configuration;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitedAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationProvider delegate;
    private final Map<String, Instant> cache = new ConcurrentHashMap<>();

    public RateLimitedAuthenticationProvider(AuthenticationProvider delegate) {
        this.delegate = delegate;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var parentAuth = delegate.authenticate(authentication);
        if (parentAuth == null) return null;
        if (update(parentAuth)) {
            return parentAuth;
        }
        throw new BadCredentialsException("Too fast!!!");
    }

    private boolean update(Authentication parentAuth) {
        Instant now = Instant.now();
        Instant previousTime = cache.get(parentAuth.getName());
        cache.put(parentAuth.getName(), now);
        return previousTime == null || previousTime.plus(Duration.ofMinutes(1)).isBefore(now);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return delegate.supports(authentication);
    }
}
