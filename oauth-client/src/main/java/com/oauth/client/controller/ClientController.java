package com.oauth.client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

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



    @GetMapping("/securedPage")
    public ModelAndView securedPage(OAuth2Authentication authentication) {
        return new ModelAndView("securedPage").addObject("authentication", authentication);
    }

    @GetMapping(value = "/remoteApi/read", produces = "application/json")
    public Object  remoteApiRead() {
        String url = "http://localhost:9091/user/common/read";
        Map forObject = oAuth2RestTemplate.getForObject(url, Map.class);
        return forObject;
    }

    @GetMapping(value = "/remoteApi/write", produces = "application/json")
    public Object remoteApiWrite() {
        String url = "http://localhost:9091/user/common/write";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map forObject = oAuth2RestTemplate.postForObject(url, headers, Map.class);
        return forObject;
    }

    @GetMapping(value = "/remoteApi/admin", produces = "application/json")
    public Object remoteApiAdmin() {
        String url = "http://localhost:9091/user/admin";
        Map forObject = oAuth2RestTemplate.getForObject(url, Map.class);
        return forObject;
    }



}
