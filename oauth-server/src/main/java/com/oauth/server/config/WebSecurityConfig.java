package com.oauth.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;
import java.io.PrintWriter;

//TODO BY Cheng Yufei <-2020-11-18 14:20->
// logout退出后仍能访问接口、角色继承无效



/**
 *
 * @author Cheng Yufei
 * @create 2020-10-29 16:15
 **/
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private DataSource dataSource;
    @Autowired
    private ObjectMapper objectMapper;

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
     * 2.登录成功回调，发生重定向，【defaultSuccessUrl 、successForwardUrl，两个只设置一个属性即可】
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
     * 4. 若使用登录成功重定向时，如果用client的接口A进行访问的时，需要在 oauth_client_details 对应client的redirect_url添加A，否则成功后跳转回A，
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
                .and().csrf().disable()
                .sessionManagement().maximumSessions(1);
    }

    /**
     * 登录成功后返回用户信息 ,利用 successHandler ，参数中的request 可以实现服务端的直接跳转【request.getRequestDispatcher().forward()，客户端请求地址不发生变化，由服务器去请求另一个资源，返回前端】,
     * 参数中的response 可以实现客户端间接跳转【response.sendRedirect()，客户端会根据地址再次进行请求，总共发出两次http请求】,也可以返回json数据。
     *
     * @param http
     * @throws Exception
     */
    //@Override
    protected void configure1(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated()
                .and().formLogin().loginPage("/login.html")
                .loginProcessingUrl("/doLogin")
                .usernameParameter("uname")
                .passwordParameter("pwd")

                //登录成功处理
                .successHandler((request, response, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    response.setContentType("application/json; charset=UTF-8");
                    PrintWriter writer = response.getWriter();
                    writer.write(objectMapper.writeValueAsString(principal));
                    writer.close();
                })

                //处理登录失败
                .failureHandler((request, response, authenticationException) -> {
                    response.setContentType("application/json; charset=UTF-8");
                    PrintWriter writer = response.getWriter();
                    //writer.write(authenticationException.getMessage());
                    ObjectNode objectNode = objectMapper.createObjectNode();
                    objectNode.put("code", -1);
                    objectNode.put("msg", "用户名或密码错误");
                    writer.println(objectNode.toString());
                    writer.close();
                })
                .permitAll()

                //设置未认证情况, 提示未登录信息，否则默认是重定向到登录页
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((request, response, authenticationException) -> {
                    response.setContentType("application/json; charset=UTF-8");
                    PrintWriter writer = response.getWriter();
                    //writer.write(authenticationException.getMessage());
                    ObjectNode objectNode = objectMapper.createObjectNode();
                    objectNode.put("code", -1);
                    objectNode.put("msg", "未登录，请先登录");
                    writer.println(objectNode.toString());
                    writer.close();
                })

                //退出登录成功，提示信息，否则默认是重定向到登录页
                .and().logout()
                .logoutSuccessHandler((request, response, authentication) -> {
                    Object principal = authentication.getPrincipal();
                    response.setContentType("application/json; charset=UTF-8");
                    PrintWriter writer = response.getWriter();
                    //writer.write(authenticationException.getMessage());
                    ObjectNode objectNode = objectMapper.createObjectNode();
                    objectNode.put("code", 0);
                    objectNode.put("msg", "退出成功");
                    writer.write(objectNode.toString());
                    writer.flush();
                    writer.close();
                })
                .deleteCookies()
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .permitAll()
                .and().csrf().disable()
        ;
    }
}
