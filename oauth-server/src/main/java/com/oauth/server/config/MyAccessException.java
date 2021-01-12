package com.oauth.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 自定义授权异常
 * @author Cheng Yufei
 * @create 2021-01-12 9:48 上午
 **/
@Component
public class MyAccessException implements AccessDeniedHandler {
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        PrintWriter writer = response.getWriter();
        //writer.write(authenticationException.getMessage());
        ObjectNode objectNode = objectMapper.createObjectNode();
        objectNode.put("code", -99);
        objectNode.put("msg", "无权访问");
        writer.println(objectNode.toString());
        writer.close();
    }
}
