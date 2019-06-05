
package com.ruisdata.springsecurityoauth2.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author zhailiang
 *
 */
@Configuration
public class WebConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .apply(smsCodeAuthenticationSecurityConfig)
                .and()
                .authorizeRequests()
                .antMatchers(
                        SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE
                )
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .csrf().disable();

    }

}
