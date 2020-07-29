package com.codeconfessions.springsecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()//Authorize Request
                .antMatchers("/", "index", "/css/*", "/js/*") // with specific patters
                .permitAll() //to allow without authentication
                .anyRequest()  //All the Request
                .authenticated() // Must be authenticated
                .and()
                .httpBasic(); //Using Basic Auth Mechanism
    }
}
