package com.company.springsecuritydemo.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class RobotFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        System.out.println("Hello from RobotFilter");

        // 1. Normal request should be process
        if (!Collections.list(request.getHeaderNames()).contains("x-robot-password")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Request with not match x-robot-password value should be denied
        String robotPassword = request.getHeader("x-robot-password");
        if (!"ping-pong".equals(robotPassword)) {
            response.getWriter().write("You are not Robot!");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        // 3. Process robot request on password matching
        SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
        emptyContext.setAuthentication(new RobotAuthentication());
        SecurityContextHolder.setContext(emptyContext);

        filterChain.doFilter(request, response);
    }
}
