package com.oauth.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;
import java.io.PrintWriter;

/**
 * 有登录验证码的
 * @author Cheng Yufei
 * @create 2020-11-26 5:00 下午
 **/
//@Configuration
public class WebSecurityConfigTwo extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .passwordEncoder(new BCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAt(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                //获取验证码接口无需校验
                .antMatchers("/demo/produceCode**").permitAll()
                .anyRequest().authenticated()
                .and().formLogin()
                .and().csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**","/css/**","/images/**");
    }

    /**
     * 将自定义的Provide添加到ProvideManage。注意要设置UserDetailsService 否则在登录时候找不到UserDetailsService ，NPE。
     * @return
     * @throws Exception
     */
    @Override
    @Bean(name="authenticationManager")
    protected AuthenticationManager authenticationManager() throws Exception {
        MyAuthenticationProvider myAuthenticationProvider = new MyAuthenticationProvider();
        myAuthenticationProvider.setUserDetailsService(userDetailsService());
        myAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        ProviderManager providerManager = new ProviderManager(Lists.newArrayList(myAuthenticationProvider));
        return providerManager;
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        return jdbcUserDetailsManager;
    }

    @Bean
    CustomAuthenticationFilter customAuthenticationFilter() throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter();
        customAuthenticationFilter.setAuthenticationManager(authenticationManager());
        customAuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            Object principal = authentication.getPrincipal();
            response.setContentType("application/json; charset=UTF-8");
            PrintWriter writer = response.getWriter();
            writer.write(objectMapper.writeValueAsString(principal));
            writer.close();
        });
        customAuthenticationFilter.setAuthenticationFailureHandler((request, response, authenticationException) -> {
            response.setContentType("application/json; charset=UTF-8");
            PrintWriter writer = response.getWriter();
            ObjectNode objectNode = objectMapper.createObjectNode();
            objectNode.put("code", -1);
            objectNode.put("msg", authenticationException.getMessage());

            writer.println(objectNode.toString());
            writer.close();
        });
        customAuthenticationFilter.setFilterProcessesUrl("/doLogin");
        return customAuthenticationFilter;

    }
}
