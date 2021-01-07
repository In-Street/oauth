package com.oauth.server.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 * @author Cheng Yufei
 * @create 2021-01-07 9:52 上午
 **/
@Configuration
public class CorsConfig {

    /**
     * spring security 跨域解决：
     *   A.
     *     1。设置 FIlter 或者 implements WebMvcConfigurer 重写addCorsMappings方法
     *     2。WebSecurityConfig 中，添加 .and().cors()
     *   B.
     *      1. 创建 CorsConfigurationSource Bean
     *      2。WebSecurityConfig 中，添加 .and().cors()
     *
     * @return
     */
    @Bean
    public FilterRegistrationBean cors() {
        OncePerRequestFilter requestFilter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
                response.setHeader("Access-Control-Allow-Origin", "*");
                response.setHeader("Access-Control-Allow-Credentials", "true");
                response.setHeader("Access-Control-Allow-Methods", "POST, GET, PATCH, DELETE, PUT");
                response.setHeader("Access-Control-Max-Age", "3600");
                response.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
                filterChain.doFilter(request, response);
            }
        };
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(requestFilter);
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }

    /**
     * 解决OAuth2跨域【eg：/oauth/token出现跨域】，同时添加 .and().cors()
     * @return
     */
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.addAllowedOrigin("*");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();
        configurationSource.registerCorsConfiguration("/**",corsConfiguration);
        return new CorsFilter(configurationSource);
    }
}
