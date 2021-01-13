package com.oauth.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.PrintWriter;

//TODO BY Cheng Yufei <-2020-11-18 14:20->
// logout退出后仍能访问接口、角色继承无效、指定接口使用fullyAuthenticated 无效


/**
 * 配置用户登录相关
 * @author Cheng Yufei
 * @create 2020-10-29 16:15
 **/
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private DataSource dataSource;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private RedisIndexedSessionRepository sessionRepository;
    @Autowired
    private MyAccessException myAccessException;

    @Bean(name = "userDetailsService")
    @Override
    public UserDetailsService userDetailsService() {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean(name = "userDetailsService2")
    public UserDetailsService userDetailsService2() {
        return new InMemoryUserDetailsManager(User.builder().username("Taylor")
                .password("$2a$10$K.9W0tEm3/k6zQYGWeQEiOlS5O05lw02VVmeCPoC4.KiU/VKT4M3C").roles("USER").build());
    }

    /**
     * user 多数据源配置: 提供多个DaoAuthenticationProvider，每个对应一个数据源，统一由ProviderManager管理即可
     * @return
     * @throws Exception
     */
    @Bean(name = "authenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        //数据源1
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        daoAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder());

        ////数据源2
        DaoAuthenticationProvider daoAuthenticationProvider2 = new DaoAuthenticationProvider();
        daoAuthenticationProvider2.setUserDetailsService(userDetailsService2());
        daoAuthenticationProvider2.setPasswordEncoder(new BCryptPasswordEncoder());

        ProviderManager providerManager = new ProviderManager(Lists.newArrayList(daoAuthenticationProvider, daoAuthenticationProvider2));
        return providerManager;
        //return super.authenticationManagerBean();
    }

    /**
     * 配置用户认证方式 - 数据库方式；
     * BCryptPasswordEncoder方式保存用户密码，authenticationManagerBean使用super。
     *
     * 或 创建 Bean authenticationManagerBean时指定数据源。
     * @param auth
     * @throws Exception
     *
     */
    //@Override
    protected void configure2(AuthenticationManagerBuilder auth) throws Exception {

        /* 内存配置登录用户，方便测试
        auth.inMemoryAuthentication()
                .withUser("sang")
                .password(passwordEncoder().encode("123"))
                .roles("admin")
                .and()
                .withUser("javaboy")
                .password(passwordEncoder().encode("123"))
                .roles("user");*/
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .passwordEncoder(new BCryptPasswordEncoder());
    }

    /**
     * 1.自定义表单登录,常用于静态资源放行，此方式不会走spring  security的过滤链。
     *
     * 2. configure(HttpSecurity http) 中常用于接口的放行，此方式 是在spring  security的过滤链中进行放行。
     * eg：将登录接口使用静态资源放行方式的话，不走过滤链，那么用户信息也不会存在SecurityContextHolder，后续也将无法获取用户信息。
     * 【
     *       获取用户信息的两种方式：a.SecurityContextHolder.getContext().getAuthentication()。
     *                                           b. Controller 方法中添加 Authentication 参数。
     * 】
     *
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
     * 2.登录成功回调，发生重定向，【defaultSuccessUrl 、successForwardUrl，两个只设置一个属性即可。不设置的话会找index.html】
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
     * 4. 若使用登录成功重定向时，如果用client的接口A进行访问的时，需要在 oauth_client_details 对应client的redirect_url添加A，否则成功后跳转回A，此时在调用其他接口B后，返回不包含在redirect_url中，再次访问A也会返回
     *     不包含在redirect_url中。
     *
     *  5. 记住我：
     *         a.核心是存在cookie中的令牌，这个令牌突破了 session 的限制，即使服务器重启、浏览器关闭又重新打开，只要这个令牌没有过期，就能访问到数据。
     *         b. cookie中携带 remember-me=xxxx, 的base64字符串。格式为：用户名:时间戳:MD5值。时间戳是一个两周后的毫秒值。
     *              MD5的明文为：username + ":" + tokenExpiryTime + ":" + password + ":" + key。服务端解析cookie中的用户名和过期时间，根据用户名查找密码，MD5计算出散列值，和前端传过来的值比较，检验令牌是否有效。
     * @throws Exception
     */

    //@Override
    protected void configure1(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //fullyAuthenticated 无效，待研究
                .antMatchers("/user/common/read").fullyAuthenticated()
                .anyRequest().authenticated()
                //选定自己的login页面，登录相关的页面及接口不进行拦截;
                //security会同时添加 GET：/login.html 接口访问页面 和 POST: /login.html接口接受登录表单提交，两个地址相同的接口；可通过 .loginProcessingUrl("")单独定义表单数据提交接口名称
                .and()
                .formLogin()
                /*  .loginPage("/login.html")
                  .loginProcessingUrl("/doLogin")
                  //自定义页面中的用户名
                  .usernameParameter("uname")
                  .passwordParameter("pwd")
                  //登录成功后跳转地址
                  .defaultSuccessUrl("/demo/index")
                  //跳转自定义登录页等需要添加permitAll()
                  .permitAll()*/

                //记住我功能，自动登录
                .and()
                .rememberMe()
                //key 默认值是一个 UUID 字符串，在服务重启后key会变，会导致之前的自动登录令牌失效，所以需要指定一个固定的key值。
                .key("gameofthrones")
                .tokenRepository(persistentTokenRepository())

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
                //允许同一账号多端登录时【多端情况下输入完用户名、密码可以登录成功】，此设置禁止同一用户多端登录，一端登录另一段会强制下线
                .sessionManagement().maximumSessions(1)
                //禁止同一账号的多端登录【在输入完用户名、密码后直接提示登录不了】，不允许有同一账号的新登录
                .maxSessionsPreventsLogin(true)
        ;
    }

    /**
     * 1.登录成功后返回用户信息 ,利用 successHandler ，参数中的request 可以实现服务端的直接跳转【request.getRequestDispatcher().forward()，客户端请求地址不发生变化，由服务器去请求另一个资源，返回前端】,
     * 参数中的response 可以实现客户端间接跳转【response.sendRedirect()，客户端会根据地址再次进行请求，总共发出两次http请求】,也可以返回json数据。
     *
     * 2. 使用接口访问 /doLogin 接口登录时，默认只能用地址后面拼接 /doLogin?uname=admin&pwd=admin 进行用户名和密码的传递，可通过自定义过滤器来实现通过json传递
     *
     * @param http
     * @throws Exception
     */

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //因为使用customAuthenticationFilter取代UsernamePasswordAuthenticationFilter，
        // 且ConcurrentSessionFilter 用到了SessionRegistryImpl，所以需要重新设置ConcurrentSessionFilter，使用自定义的SessionRegistry及信息返回
        //http.addFilterAt(new ConcurrentSessionFilter(sessionRegistryImpl(), strategy -> {
        http.addFilterAt(new ConcurrentSessionFilter(springSessionBackedSessionRegistry(), strategy -> {
            HttpServletResponse response = strategy.getResponse();
            response.setContentType("application/json;charset=UTF-8");
            PrintWriter writer = response.getWriter();
            ObjectNode objectNode = objectMapper.createObjectNode();
            objectNode.put("code", -1);
            objectNode.put("msg", "账号在另一台设备登录，本次登录下线");
            writer.println(objectNode.toString());
            writer.close();
        }), ConcurrentSessionFilter.class);

        //自定义登录的过滤器实现json传输用户名、密码。代替UsernamePasswordAuthenticationFilter
        http.addFilterAt(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        //authorizeRequests放在首位表示此过滤链的过滤路径是/**
        //http.antMatchers("/foo/**").authorizeRequests():表示此过滤链的过滤路径是/foo下的请求
        http.authorizeRequests()
                //不登录时允许访问的接口
                .antMatchers("/demo/produceCode", "/demo/setSession", "/demo/getSession","/demo/onlineNum").permitAll()
                .antMatchers("/demo/accessDenied").hasAuthority("ADMIN")
                .anyRequest().authenticated()
                .and()
                //配置表单登录细节
                .formLogin()
                //.loginPage("/login.html")
                //.loginProcessingUrl("/doLogin")
                //.usernameParameter("uname")
                //.passwordParameter("pwd")

                //登录成功处理
                /*    .successHandler((request, response, authentication) -> {
                        Object principal = authentication.getPrincipal();
                        response.setContentType("application/json; charset=UTF-8");
                        PrintWriter writer = response.getWriter();
                        writer.write(objectMapper.writeValueAsString(principal));
                        writer.close();
                    })*/

                //处理登录失败
                /* .failureHandler((request, response, authenticationException) -> {
                     response.setContentType("application/json; charset=UTF-8");
                     PrintWriter writer = response.getWriter();
                     //writer.write(authenticationException.getMessage());
                     ObjectNode objectNode = objectMapper.createObjectNode();
                     objectNode.put("code", -1);
                     objectNode.put("msg", "用户名或密码错误");
                     writer.println(objectNode.toString());
                     writer.close();
                 })*/
                .permitAll()

                //设置未认证情况, 提示未登录信息，否则默认是重定向到登录页
                .and()
                .exceptionHandling()
                //自定义认证异常
                .authenticationEntryPoint((request, response, authenticationException) -> {
                    response.setContentType("application/json;charset=UTF-8");
                    PrintWriter writer = response.getWriter();
                    //writer.write(authenticationException.getMessage());
                    ObjectNode objectNode = objectMapper.createObjectNode();
                    objectNode.put("code", -1);
                    objectNode.put("msg", "未登录，请先登录");
                    writer.println(objectNode.toString());
                    writer.close();
                })
                //自定义授权异常:
                //1. 无法处理client端访问资源服务器的接口时的无权访问的情况。此时client端报OAuth2AccessDeniedException，需在client端定义异常拦截返回自定义格式。
                //2。此设置针对server端接口，且是在configure(HttpSecurity http)中定义接口的hasAuthority("")时有效。使用@PreAuthorize时自定义授权异常无效。
                .accessDeniedHandler(myAccessException)

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
                //解决跨域
                .and().cors()
                .and().csrf().disable()
                //防止会话固定攻击：默认方式migrateSession:登录成功后生成新session，将旧session信息复制到新session中。
                .sessionManagement().sessionFixation().migrateSession()
       /* .sessionManagement().maximumSessions(1).sessionRegistry(sessionRegistryImpl())
        .expiredSessionStrategy(sessionInformationExpiredEvent -> {
            HttpServletResponse response = sessionInformationExpiredEvent.getResponse();
            response.setContentType("application/json;charset=UTF-8");
            PrintWriter writer = response.getWriter();
            ObjectNode objectNode = objectMapper.createObjectNode();
            objectNode.put("code", -1);
            objectNode.put("msg", "2账号在另一台设备登录，本次登录下线2");
            writer.println(objectNode.toString());
            writer.close();
        })*/
        ;

    }

    /**
     * 自定义过滤器：1. 需要设置登录成功、失败的情况。configure(HttpSecurity http) 方法中 formLogin 相关设置的 loginProcessingUrl、登录成功、失败的设置会无效，包括session的多端登录控制也会失效。
     *                      2.如果登录接口有变化必须设置setFilterProcessesUrl("/doLogin") 登录接口，【默认是 /login】，否则此过滤器无效，仍然会走原始的UsernamePasswordAuthenticationFilter。
     * @return
     * @throws Exception
     */
    @Bean
    CustomAuthenticationFilter customAuthenticationFilter() throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter();
        customAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        customAuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            Object principal = authentication.getPrincipal();
            response.setContentType("application/json; charset=UTF-8");
            PrintWriter writer = response.getWriter();
            writer.write("认证成功：" + objectMapper.writeValueAsString(principal));
            writer.close();
        });
        customAuthenticationFilter.setAuthenticationFailureHandler((request, response, authenticationException) -> {
            response.setContentType("application/json; charset=UTF-8");
            PrintWriter writer = response.getWriter();
            ObjectNode objectNode = objectMapper.createObjectNode();
            objectNode.put("code", -1);
            objectNode.put("msg", "用户名或密码错误：" + authenticationException.getMessage());
            writer.println(objectNode.toString());
            writer.close();
        });
        customAuthenticationFilter.setFilterProcessesUrl("/doLogin");
        //禁止同一账号的多端登录
        /*ConcurrentSessionControlAuthenticationStrategy authenticationStrategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistryImpl());
        authenticationStrategy.setMaximumSessions(1);
        CompositeSessionAuthenticationStrategy compositeSessionAuthenticationStrategy = new CompositeSessionAuthenticationStrategy(Lists.newArrayList(authenticationStrategy, new SessionFixationProtectionStrategy(),
                new RegisterSessionAuthenticationStrategy(sessionRegistryImpl())));*/

        ConcurrentSessionControlAuthenticationStrategy authenticationStrategy = new ConcurrentSessionControlAuthenticationStrategy(springSessionBackedSessionRegistry());
        authenticationStrategy.setMaximumSessions(1);
        CompositeSessionAuthenticationStrategy compositeSessionAuthenticationStrategy = new CompositeSessionAuthenticationStrategy(Lists.newArrayList(authenticationStrategy, new SessionFixationProtectionStrategy(),
                new RegisterSessionAuthenticationStrategy(springSessionBackedSessionRegistry())));
        customAuthenticationFilter.setSessionAuthenticationStrategy(compositeSessionAuthenticationStrategy);
        return customAuthenticationFilter;
    }

    /**
     * spring security 提供实现。
     * 使用内存维护用户会话信息。分布式情况下，登录的session存于各自的ConcurrentHashMap中，无法控制同一用户只登录一端。
     * @return
     */
   /* @Bean(name = "sessionRegistry")
    public SessionRegistryImpl sessionRegistryImpl() {
        return new SessionRegistryImpl();
    }*/

    /**
     * spring session 提供实现。
     * 使用redis维护用户会话信息，分布式环境下可控制同一用户只登录一端。
     * @return
     */
    @Bean(name = "sessionRegistry")
    public SpringSessionBackedSessionRegistry springSessionBackedSessionRegistry() {
        return new SpringSessionBackedSessionRegistry(sessionRepository);
    }

    /**
     * jdbc 记录 remember me 的令牌信息
     * @return
     */
    @Bean(name = "persistentTokenRepository")
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }

    /**
     * 1.设置这个Bean目的是为了在设置了.maxSessionsPreventsLogin(true)来禁止同一账号的新登录情况时，已登录用户在logout后，另一段可以马上进行登录。
     *  否则感知不到已注销，另一端也无法及时可以登录。
     *
     *  2. 在spring security 中，通过监听session销毁事件，来及时清理session记录。默认的失效是通过调用 StandardSession#invalidate 方法来实现的，
     *     这一个失效事件无法被 Spring 容器感知到，进而导致当用户注销登录之后，Spring Security 没有及时清理会话信息表，以为用户还在线，进而导致用户无法重新登录进来。
     *
     *  3. 当使用redis来控制session时，无需设置此bean。否则报【FindByIndexNameSessionRepository “RedisConnectionFactory is required”】
     * @return
     */
   /* @Bean(name = "httpSessionEventPublisher")
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }*/
}
