package com.oauth.client.controller;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.List;
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
    private RestTemplate restTemplate;


    @GetMapping("/securedPage")
    public ModelAndView securedPage(OAuth2Authentication authentication) {
        return new ModelAndView("securedPage").addObject("authentication", authentication);
    }

    @GetMapping(value = "/remoteApi/read", produces = "application/json")
    public Object remoteApiRead() {
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

    @GetMapping(value = "/remoteApi/writerName", produces = "application/json")
    public Object remoteApiWriterName() {
        String url = "http://localhost:9091/user/writeName";
        Map forObject = oAuth2RestTemplate.getForObject(url, Map.class);
        return forObject;
    }

    @GetMapping(value = "/remoteApi/writeAge", produces = "application/json")
    public Object remoteApiWriteAge(@RequestParam Integer age) {
        String url = "http://localhost:9091/user/writeAgeGt?age=" + age;
        Map forObject = oAuth2RestTemplate.getForObject(url, Map.class);
        return forObject;
    }

    @GetMapping(value = "/remoteApi/writePreFilter", produces = "application/json")
    public Object remoteApiWritePreFilter() {
        String url = "http://localhost:9091/user/writePreFilter?ages={ages}&users={users}";
        HashMap<String, Object> map = new HashMap<>();
        map.put("ages", "1, 2, 5, 6, 7, 8");
        map.put("users", "taylor·swift,Candice");
        // template 访问接口，传参使用占位符的同时需要将Map的key定位String类型，否则报：not enough variable values available to expand
        Map forObject = oAuth2RestTemplate.getForObject(url, Map.class, map);
        return forObject;
    }

    @GetMapping(value = "/remoteApi/writePostFilter", produces = "application/json")
    public Object remoteApiWritePostFilter() {
        String url = "http://localhost:9091/user/writePostFilter";
        List forObject = oAuth2RestTemplate.getForObject(url, List.class);
        return forObject;
    }

    @GetMapping(value = "/remoteApi/commonRest/write", produces = "application/json")
    public Object remoteApiWrite2() {
        String url = "http://localhost:9091/user/common/write";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map forObject = restTemplate.postForObject(url, headers, Map.class);
        return forObject;
    }
}
