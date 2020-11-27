package com.oauth.client.controller;

import com.google.code.kaptcha.Producer;
import com.google.common.collect.ImmutableMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

/**
 *
 * @author Cheng Yufei
 * @create 2020-11-06 17:21
 **/
@RestController
public class ClientController {

    @Autowired
    private OAuth2RestTemplate oAuth2RestTemplate;
    @Autowired
    private Producer producer;


    @GetMapping("/securedPage")
    public ModelAndView securedPage(OAuth2Authentication authentication) {
        return new ModelAndView("securedPage").addObject("authentication", authentication);
    }

    @GetMapping("/remoteApi/read")
    public Object remoteApiRead() {
        String url = "http://localhost:9091/user/common/read";
        Map forObject = oAuth2RestTemplate.getForObject(url, Map.class);
        return forObject;
    }

    @GetMapping("/remoteApi/write")
    public Object remoteApiWrite() {
        String url = "http://localhost:9091/user/common/write";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map forObject = oAuth2RestTemplate.postForObject(url, headers, Map.class);
        return forObject;
    }

    @GetMapping("/remoteApi/admin")
    public Object remoteApiAdmin() {
        String url = "http://localhost:9091/user/admin";
        Map forObject = oAuth2RestTemplate.getForObject(url, Map.class);
        return forObject;
    }

    @GetMapping("/produceCode")
    public void produceCode(HttpServletResponse response, HttpSession session) throws IOException {
        response.setContentType("image/jpeg");
        String text = producer.createText();
        session.setAttribute("verify_code", text);
        BufferedImage image = producer.createImage(text);
        ServletOutputStream outputStream = response.getOutputStream();
        ImageIO.write(image, "jpg", outputStream);
        outputStream.close();
    }

}
