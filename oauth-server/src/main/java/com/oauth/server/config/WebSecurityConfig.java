package com.oauth.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

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
	 * 1.and()：表示结束标签，上下文回到HttpSecurity，开启新一轮配置;
	 * 2.登录成功回调，【defaultSuccessUrl 、successForwardUrl，两个只设置一个属性即可】
	 * 			a. defaultSuccessUrl：如果从登录地址访问，登录成功后跳转到指定地址，如果从其他地址/A访问，因未登录重定向到登录地址，登录成功后回跳转到原来的/A，而不是指定的地址。但当defaultSuccessUrl第二个参数设置为
	 * 											true时，效果和successForwardUrl效果一致。
	 *
	 * 			b.successForwardUrl: 不管从哪个地址进行请求，登录成功后都会跳转到指定地址。
	 *
	 * 3. 登录失败回调：【 failureForwardUrl、failureUrl 】
	 *		a. failureForwardUrl：登录失败之后会发生服务端跳转
	 *		b. failureUrl: 登录失败之后，会发生重定向
	 *
	 * 3.登出接口默认: /logout
	 * 		a. logoutRequestMatcher() ：不仅可以修改登出地址，还可以指定请求方式，和 logoutUrl() 选一个配置即可；
	 *
	 *
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

				.and().logout()
				//修改注销地址和请求方式
				//.logoutRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.POST.name()))
				//注销成功后跳转
				//.logoutSuccessUrl("")
				//清除cookie
				.deleteCookies()
				.permitAll()
				//关闭csrf
				.and().csrf().disable();
	}
}
