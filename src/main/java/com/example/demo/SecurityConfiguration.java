package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public interface SecurityConfiguration {
    @Bean
    static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    void configure (HttpSecurity http) throws Exception;

    void configure(AuthenticationManagerBuilder auth) throws Exception;
}
