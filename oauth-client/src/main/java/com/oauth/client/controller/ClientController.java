package com.oauth.client.controller;

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

import javax.servlet.http.HttpServletRequest;
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


    @GetMapping("/securedPage")
    public ModelAndView securedPage(OAuth2Authentication authentication) {
        return new ModelAndView("securedPage").addObject("authentication", authentication);
    }

    @GetMapping("/remoteApi")
    public Object remoteApi(@RequestParam String type) throws URISyntaxException {
        String url = "http://localhost:9091";
        Map forObject = null;
        switch (type) {
            case "read":
                url = url + "/user/common/read";
                forObject = oAuth2RestTemplate.getForObject(url, Map.class);
                break;
            case "write":
                url = url + "/user/common/write";
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                forObject = oAuth2RestTemplate.postForObject(url, headers, Map.class);
                break;
            case "admin":
                url = url + "/user/admin";
                forObject = oAuth2RestTemplate.getForObject(url, Map.class);
                break;
            default:
                break;
        }

        return forObject;
    }

}
