package com.oauth.client.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 *
 * @author Cheng Yufei
 * @create 2021-01-12 10:27 上午
 **/
@RestControllerAdvice
public class GlobalException extends ResponseEntityExceptionHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @ExceptionHandler(value = OAuth2AccessDeniedException.class)
    public void accessDenied(HttpServletResponse response) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        PrintWriter writer = response.getWriter();
        //writer.write(authenticationException.getMessage());
        ObjectNode objectNode = objectMapper.createObjectNode();
        objectNode.put("code", -2);
        objectNode.put("msg", "无权访问");
        writer.println(objectNode.toString());
        writer.close();
    }

}
