package com.oauth.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 *自定义过滤器，实现用户名和密码通过 json body传递
 * @author Cheng Yufei
 * @create 2020-11-24 10:58 上午
 **/
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if ("POST".equals(request.getMethod()) && request.getRequestURI().equals("/doLogin")
        && (MediaType.APPLICATION_JSON_VALUE.equals(request.getContentType()) || MediaType.APPLICATION_JSON_UTF8_VALUE.equals(request.getContentType()))) {
            try {
                //从请求json中获取用户名、密码
                ServletInputStream inputStream = request.getInputStream();
                ObjectMapper objectMapper = new ObjectMapper();
                Map map = objectMapper.readValue(inputStream, Map.class);
                String uname = String.valueOf(map.get("uname"));
                String pwd = String.valueOf(map.get("pwd"));

                //构建对象，模仿 UsernamePasswordAuthenticationFilter 类中的处理流程
                UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(uname, pwd);
                setDetails(request, authRequest);
                //验证
                return getAuthenticationManager().authenticate(authRequest);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return super.attemptAuthentication(request, response);
    }
}
