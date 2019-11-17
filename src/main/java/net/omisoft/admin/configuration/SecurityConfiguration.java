package net.omisoft.admin.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final String hasIpRangeAccessExpresion;

    public SecurityConfiguration(@Value("${app.ip.whitelist}") List<String> ipWhitelist) {
        hasIpRangeAccessExpresion = ipWhitelist.stream()
                .collect(Collectors.joining("') or hasIpAddress('", "hasIpAddress('", "')"));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl("/");

        http.authorizeRequests()
                .antMatchers("/assets/**").permitAll()
                //TODO delete line -> "If you protect the /instances endpoint don’t forget to configure the username and password on your SBA-Client using spring.boot.admin.client.username and spring.boot.admin.client.password."
                .antMatchers("/instances/**").access("isAuthenticated() or " + hasIpRangeAccessExpresion)
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login").successHandler(successHandler)
                .and()
                .logout().logoutUrl("/logout")
                .and()
                .httpBasic()
                .and()
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringAntMatchers(
                        "/instances",
                        "/actuator/**"
                );
    }

}
