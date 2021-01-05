package com.oauth.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.FastDateFormat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 *自定义过滤器，实现用户名和密码通过 json body传递
 * @author Cheng Yufei
 * @create 2020-11-24 10:58 上午
 **/
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    private SessionRegistry sessionRegistry;

    private FastDateFormat dateFormat = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss");
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if ("POST".equals(request.getMethod()) && request.getRequestURI().equals("/server/doLogin")
                && (MediaType.APPLICATION_JSON_VALUE.equals(request.getContentType()) || MediaType.APPLICATION_JSON_UTF8_VALUE.equals(request.getContentType()))) {
            //从请求json中获取用户名、密码
            ObjectMapper objectMapper = new ObjectMapper();
            ServletInputStream inputStream = null;
            Map map = null;
            try {
                inputStream = request.getInputStream();
                map = objectMapper.readValue(inputStream, Map.class);
            } catch (IOException e) {
                e.printStackTrace();
            }
            String uname = String.valueOf(map.get("uname"));
            String pwd = String.valueOf(map.get("pwd"));
            Object code = map.get("code");
            Object verifyCode = request.getSession().getAttribute("verify_code");
            if (Objects.isNull(code) || Objects.isNull(verifyCode) || !Objects.equals(code, verifyCode)) {
                throw new AuthenticationServiceException("验证码错误");
            }

            //构建对象，模仿 UsernamePasswordAuthenticationFilter 类中的处理流程
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(uname, pwd);
            setDetails(request, authRequest);

            //将用户会话注册进session管理器中，用于多端登录的控制
            sessionRegistry.registerNewSession(request.getSession().getId(), new User(uname, pwd, authRequest.getAuthorities()));
          /*  List<Object> allPrincipals = sessionRegistry.getAllPrincipals();
            allPrincipals.stream().forEach(p -> {
                List<SessionInformation> allSessions = sessionRegistry.getAllSessions(p, false);
                allSessions.stream().forEach(s -> {
                    System.out.println(s.getPrincipal() + ">>" + s.getSessionId() + ">>" + s.isExpired()
                    +">>"+dateFormat.format(s.getLastRequest()));
                });
            });*/
            //验证
            return getAuthenticationManager().authenticate(authRequest);
        }
        return super.attemptAuthentication(request, response);
    }
}
