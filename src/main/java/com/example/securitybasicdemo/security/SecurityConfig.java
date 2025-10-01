package com.example.securitybasicdemo.security;

import com.example.securitybasicdemo.jwt.AuthEntryPointJwt;
import com.example.securitybasicdemo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Autowired
    DataSource dataSource;
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())  // allow Security to use your WebMvcConfigurer CORS config
                .authorizeHttpRequests(auth -> auth
                        //.requestMatchers("/h2-console/**").permitAll() // allow H2 console
                        .requestMatchers("/signin").permitAll()
                        .requestMatchers("/refresh").permitAll() // allow refresh token requests
                        .requestMatchers("/logout").permitAll()  // allow logout request
                        .requestMatchers("/api/public/**").permitAll()    //publically accessible API's
                        .anyRequest().authenticated()                 // secure all other endpoints
                );
        http.sessionManagement(
                session-> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS)
        );
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        http.logout(logout -> logout.disable())          // disable default logout
            .formLogin(form -> form.disable());          // disable form login
        //http.httpBasic(withDefaults());

        // Allow frames for H2 console
        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.sameOrigin())
        );

        // Disable CSRF for H2 console
        //http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));
        //http.csrf(csrf -> csrf.ignoringRequestMatchers("/signin"));
        http.csrf(csrf -> csrf.disable());

        http.addFilterBefore(authenticationJwtTokenFilter(),UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    /* Good for learning project, not good for production grade application, we might need to create endpoint and register user
    with database.*/

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

            if(!manager.userExists("user")){
                UserDetails user = User.withUsername("user")
                        .password(passwordEncoder().encode("password"))
                        .roles("USER")
                        .build();
                userDetailsManager.createUser(user);
            }
            if(!manager.userExists("admin")){
                UserDetails admin = User.withUsername("admin")
                        //.password(passwordEncoder().encode("adminPass"))
                        .password(passwordEncoder().encode("admin"))
                        .roles("ADMIN")
                        .build();
                userDetailsManager.createUser(admin);
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}