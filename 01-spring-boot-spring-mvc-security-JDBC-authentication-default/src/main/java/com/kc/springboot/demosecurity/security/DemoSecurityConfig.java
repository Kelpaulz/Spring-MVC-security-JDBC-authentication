package com.kc.springboot.demosecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

//Because username and password are defined here, spring boot won't use the password on the application.properties
//This code allows us to use username and password from the database and even use customised tables
@Configuration
public class DemoSecurityConfig {
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        //define query to retrieve a user by username
        jdbcUserDetailsManager.setUsersByUsernameQuery(
                "select user_id, pw, active from members where user_id=?"
        );

        //define query to retrieve the authorities/roles by username
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                "select user_id, role from roles where user_id=?"
        );

        return jdbcUserDetailsManager; // Tells spring to use JDBC authentication wth our data source
    }

//    We commented this code out because they were hard coded, and now I want to use JDBC to work directly with the databases. Using Mysql in this case
//    @Bean
//    public InMemoryUserDetailsManager userDetailsManager(){
//        UserDetails john = User.builder()
//                .username("john")
//                .password("{noop}test123")
//                .roles("EMPLOYEE")
//                .build();
//
//        UserDetails mary = User.builder()
//                .username("mary")
//                .password("{noop}test123")
//                .roles("EMPLOYEE","MANAGER")
//                .build();
//
//        UserDetails susan = User.builder()
//                .username("susan")
//                .password("{noop}test123")
//                .roles("EMPLOYEE","MANAGER","ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(john, mary, susan);
//    }



    //To modify spring security configuration to use custom login form
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(configurer -> configurer
                        .requestMatchers("/").hasRole("EMPLOYEE") //Anyone with the employee role can access the home page url link
                        .requestMatchers("/leaders/**").hasRole("MANAGER")//managers can access the leaders URL. The ** means all subdirectories
                        .requestMatchers("/systems/**").hasRole("ADMIN")//Admins can access the leaders URL. The ** means all subdirectories
                        .anyRequest().authenticated()) //Any request to the app must be authenticated
                .formLogin(form->form
                        .loginPage("/showMyLoginPage") //show our custom form at the request mapping. This will need a controller mapping
                        .loginProcessingUrl("/authenticateTheUser") //the custom login form will post the data to this URL for processing. handled by spring hence controller mapping is not required
                        .permitAll())
                .logout(logout -> logout.permitAll())
                .exceptionHandling(configurer -> configurer.accessDeniedPage("/access-denied"));
        return http.build();
    }
}
