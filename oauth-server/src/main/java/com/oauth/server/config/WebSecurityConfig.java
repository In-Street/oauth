package com.oauth.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.sql.DataSource;

/**
 *
 * @author Cheng Yufei
 * @create 2020-10-29 16:15
 **/
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


	@Autowired
	private DataSource dataSource;

	@Bean(name = "authenticationManager")
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	/**
	 * 配置用户认证方式 - 数据库方式；
	 * BCryptPasswordEncoder方式保存用户密码
	 * @param auth
	 * @throws Exception
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
				.dataSource(dataSource)
				.passwordEncoder(new BCryptPasswordEncoder());
	}

	/**
	 * 自定义表单登录,忽略一些静态文件
	 * @param web
	 * @throws Exception
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
	}

	/**
	 * 自定义表单登录
	 * and()：表示结束标签，上下文回到HttpSecurity，开启新一轮配置
	 * @throws Exception
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated()
				//选定自己的login页面，登录相关的页面及接口不进行拦截;
				//security会同时添加 GET：/login.html 接口访问页面 和 POST: /login.html接口接受登录表单提交，两个地址相同的接口；可通过 .loginProcessingUrl("")单独定义表单数据提交接口名称
				.and().formLogin().loginPage("/login.html")
				.loginProcessingUrl("/doLogin")
				//自定义页面中的用户名
				.usernameParameter("uname")
				.passwordParameter("pwd")
				//登录成功后跳转地址
				.defaultSuccessUrl("/demo/index")
				.permitAll()

				.and().logout().permitAll()
				//关闭csrf
				.and().csrf().disable();
	}
}
