package com.codeconfessions.springsecurity.security;

import com.codeconfessions.springsecurity.auth.ApplicationUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.concurrent.TimeUnit;

import static com.codeconfessions.springsecurity.model.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private PasswordEncoder passwordEncoder;

    private ApplicationUserDetailService applicationUserDetailService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserDetailService applicationUserDetailService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserDetailService = applicationUserDetailService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())//This config must be added to enable to spring to generate CSRF token
                //.and()
                .csrf().disable()
                .authorizeRequests()//Authorize Request
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() // with specific patterns to allow without authentication
                .antMatchers("/api/**").hasRole(STUDENT.name())
                //.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
                //.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
                //.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
                //.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()  //All the Request
                .authenticated() // Must be authenticated
                .and()
                //.httpBasic(); //Using Basic Auth Mechanism
                .formLogin()
                    .loginPage("/login").permitAll()
                    .defaultSuccessUrl("/courses")
                    .usernameParameter("username")
                    .passwordParameter("password")
                .and()
                .rememberMe()
                    //.tokenRepository()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverystrong") //Instead of default key we are setting this key to generate a secure MD5 hash
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login")
                ;
    }

    /*@Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
                //.roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
            annaSmithUser, lindaUser, tomUser
        );
    }*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider= new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserDetailService);
        return provider;
    }
}
