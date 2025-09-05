package com.example.securitybasicdemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class FormBasedAuthController {

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
}
