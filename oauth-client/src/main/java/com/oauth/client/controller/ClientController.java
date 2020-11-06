package com.oauth.client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.util.Map;

/**
 *
 * @author Cheng Yufei
 * @create 2020-11-06 17:21
 **/
@RestController
@RequestMapping("/client")
public class ClientController {

	@Autowired
	private OAuth2RestTemplate oAuth2RestTemplate;


	@GetMapping("/securedPage")
	public ModelAndView securedPage(OAuth2Authentication authentication) {
		return new ModelAndView("securedPage").addObject("authentication", authentication);
	}

	@GetMapping("/remoteApi")
	public Object remoteApi(){
		Map forObject = oAuth2RestTemplate.getForObject("http://localhost:9091/user/read", Map.class);
		return forObject;
	}

}
