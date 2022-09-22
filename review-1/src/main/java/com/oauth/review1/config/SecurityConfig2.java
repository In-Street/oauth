package com.oauth.review1.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * json 交互使用
 * @author Cheng Yufei
 * @create 2022-09-19 15:53
 **/
//@Configuration
public class SecurityConfig2 extends WebSecurityConfigurerAdapter {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //permitAll：无需登录
                .antMatchers("/user/get")/*.permitAll()*/.hasRole("USER")
                .anyRequest().authenticated().and()
                .formLogin()
                .loginProcessingUrl("/doLogin")
                .usernameParameter("uname")
                .passwordParameter("pwd")
                //登录成功：实现 onAuthenticationSuccess 方法, authentication保存了刚刚登录的信息
                .successHandler((request, response, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    returnHandler(response, objectMapper.writeValueAsString(principal));
                })
                //登录失败
                .failureHandler((request, response, ex) -> {
                    returnHandler(response, "登录失败:" + ex.getMessage());
                })
                .and()
                .exceptionHandling()
                //未认证处理
                .authenticationEntryPoint((request, response, authenticationException) -> {
                    returnHandler(response, "未登录");
                })
                .and()
                .logout()
                .logoutSuccessHandler((request, response, authentication) -> {
                    returnHandler(response, "退出登录成功");
                })
                //.deleteCookies()
                .and()
                //不禁用csrf时，无法通过http工具访问，只能通过页面访问
                .csrf().ignoringAntMatchers("/doLogin","/logout");

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("jay").password("jay").roles("USER");
    }

    @Bean(name = "passwordEncoder")
    public PasswordEncoder passwordEncoder() {
        //return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }

    private void returnHandler(HttpServletResponse response, String msg) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        writer.write(msg);
        writer.close();
    }
}
