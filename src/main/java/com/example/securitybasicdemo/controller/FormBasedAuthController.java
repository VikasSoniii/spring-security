package com.example.securitybasicdemo.controller;


import com.example.securitybasicdemo.dto.LoginRequest;
import com.example.securitybasicdemo.dto.LoginResponse;
import com.example.securitybasicdemo.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping
public class FormBasedAuthController {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/hello")
    public String getMessage(){
        return "Hello Java!";
    }

    @PreAuthorize("hasRole('USER')") //Option 3: Role Based Authentication with Spring Security
    @GetMapping("/user")
    public String getUserEndpoint(){
        return "Hello User!";
    }

    @PreAuthorize("hasRole('ADMIN')") //Option 3: Role Based Authentication with Spring Security
    @GetMapping("/admin")
    public String getAdminEndpoint(){
        return "Hello Admin!";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", userDetails.getUsername());
        profile.put("roles", userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList()));
        profile.put("message", "This is user-specific content from backend.");

        return ResponseEntity.ok(profile);
    }
}