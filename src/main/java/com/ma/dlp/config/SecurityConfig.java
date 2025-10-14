package com.ma.dlp.config;

import com.ma.dlp.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    @Autowired
//    private CustomUserDetailsService customUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

   @Bean
    public AuthenticationProvider authenticationProvider(CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder ) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http , AuthenticationProvider authenticationProvider) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable()) // Disable CSRF for APIs

                .authenticationProvider(authenticationProvider)
                .authorizeHttpRequests(authz -> authz
                        // Public endpoints
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/agent/register").permitAll()
                        .requestMatchers( "/api/agent/login").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                                .requestMatchers("/api/agent/capabilities", "POST").permitAll()
                        .requestMatchers("/api/agent/heartbeat", "POST").permitAll()
                                .requestMatchers("/api/agent/active-policies", "GET").permitAll()
                                .requestMatchers("/api/agent/alerts", "POST").permitAll()
                                .requestMatchers("/api/agent/usb-alert", "POST").permitAll()
                        // Static resources (HTML, CSS, JS)
                        .requestMatchers("/*.html", "/*.css", "/*.js", "/favicon.ico" , "/").permitAll()

                        // Admin endpoints - require ADMIN role
                        .requestMatchers("/api/admin/**").hasAuthority("ADMIN")

//                        // Agent endpoints - require authentication
//                        .requestMatchers("/api/agent/**").authenticated()

                        // Allow all other requests (for development)
//                        .anyRequest().permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin()) // For H2 console
                );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // This is the key change. "setAllowedOriginPatterns" is more flexible than "setAllowedOrigins"
        // and is needed to correctly handle requests from "file://" and other scenarios.
//        configuration.setAllowedOriginPatterns(Arrays.asList("http://localhost:8080"));
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8080"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


}