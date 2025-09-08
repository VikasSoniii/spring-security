package com.example.securitybasicdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/h2-console/**").permitAll() // allow H2 console
                        .anyRequest().authenticated()                 // secure all other endpoints
                )
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());

        // Allow frames for H2 console
        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.sameOrigin())
        );

        // Disable CSRF for H2 console
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        // Initialize database schema (optional - better to use schema.sql)
        initializeDatabase(jdbcUserDetailsManager);

        return jdbcUserDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // For demo purposes only - use proper password encoding in production
        return new BCryptPasswordEncoder();
    }

    private void initializeDatabase(JdbcUserDetailsManager userDetailsManager) {
        // Only create users if they don't exist
        if (!userDetailsManager.userExists("user")) {
            UserDetails user1 = User.builder()
                    .username("user")
                    .password(passwordEncoder().encode("password")) // No {noop} prefix needed with NoOpPasswordEncoder
                    .roles("USER")
                    .build();
            userDetailsManager.createUser(user1);
        }

        if (!userDetailsManager.userExists("admin")) {
            UserDetails admin = User.builder()
                    .username("admin")
                    .password(passwordEncoder().encode("admin"))
                    .roles("ADMIN")
                    .build();
            userDetailsManager.createUser(admin);
        }
    }
}