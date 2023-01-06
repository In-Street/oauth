package com.oauth.review1.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.PrintWriter;

/**
 *  登录用户数据库配置， 表： users 、 authorities
 * @author Cheng Yufei
 * @create 2022-12-30 17:15
 **/
@Configuration
public class SecurityConfig6 extends WebSecurityConfigurerAdapter {

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private DataSource dataSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()

                //fullyAuthenticated：自动过登录形式不能访问接口，自动登录的需要重新输入用户名密码才能访问接口
                .antMatchers("/user/admin/**").access("fullyAuthenticated and hasRole('admin')")
                .antMatchers("/user/user").hasRole("user")

                //rememberMe(): 接口需要rememberme才能访问，用户名密码登录的不能访问
                .antMatchers("/user/remember").rememberMe()
                .anyRequest().authenticated()
                .and()
                .rememberMe()
                .key("promise")

                //令牌持久化
                .tokenRepository(jdbcTokenRepositoryImpl())
                .and()
                .formLogin()
                .loginProcessingUrl("/doLogin")
                .usernameParameter("uname")
                .passwordParameter("pwd")
                .successHandler((request, response, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    returnHandler(response, objectMapper.writeValueAsString(principal));
                })
                .failureHandler((request, response, exception) -> {
                    returnHandler(response, exception.getMessage());
                })
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((request, response, authException) -> {
                    returnHandler(response, "未登录");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    returnHandler(response, "无权限");
                })
                .and()
                .logout()
                .logoutSuccessHandler((request, response, authentication) -> {
                    returnHandler(response, "退出登录成功");
                })
                //.deleteCookies()
                .and()
                //不禁用csrf时，无法通过http工具访问，只能通过页面访问
                .csrf().ignoringAntMatchers("/doLogin", "/logout", "/login");
    }

    /**
     * 持久化令牌
     * @return
     */
    @Bean(name = "jdbcTokenRepositoryImpl")
    public JdbcTokenRepositoryImpl jdbcTokenRepositoryImpl() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }

    @Bean(name = "userDetailsService")
    public UserDetailsService userDetailsService() {
        JdbcUserDetailsManager detailsManager = new JdbcUserDetailsManager();
        detailsManager.setDataSource(dataSource);

        //不判断存在时，每次启动都会进行创建
        if (!detailsManager.userExists("admin")) {
            detailsManager.createUser(User.withUsername("admin")
                    .password("$2a$10$jH0koamV4xpRSmMi6OjKge0B3FveXLEwObL4loO7Q4SDPWvvZEVg.").roles("admin").build()
            );
        }
        if (!detailsManager.userExists("user")) {
            detailsManager.createUser(User.withUsername("user")
                    .password("$2a$10$ARZvZJVhagH0Yn0Ep54QceUidczWz923qHmzBde3BgDWxxA8rNqKi").roles("user").build()
            );
        }
        return detailsManager;
    }

    @Bean(name = "passwordEncoder")
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(name = "roleHierarchy")
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return roleHierarchy;
    }

    private void returnHandler(HttpServletResponse response, String msg) throws IOException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        writer.write(msg);
        writer.close();
    }
}
