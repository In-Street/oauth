package com.oauth.client.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 *
 * @author Cheng Yufei
 * @create 2020-11-06 15:53
 **/
/*@Configuration
@Order(101)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


	*//**
	 *  / 和/login 路径允许访问，其它路径需要身份认证后才能访问
	 * @param http
	 * @throws Exception
	 *//*
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/", "/login**","/noAuthorize**")
				.permitAll().anyRequest().authenticated();
	}
}*/
