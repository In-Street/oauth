package com.oauth.user.controller;

import com.google.common.collect.ImmutableMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 *
 * @author Cheng Yufei
 * @create 2020-11-02 15:23
 **/
@RestController
@RequestMapping("/user")
public class UserController {

	@Autowired
	private TokenStore tokenStore;

	/**
	 * 读权限或写权限可访问，返回登录用户信息
	 *
	 * @param authentication
	 * @return
	 */
	@PreAuthorize("hasAuthority('READ') or hasAuthority('WRITE')")
	@GetMapping("/read")
	public Map read(OAuth2Authentication authentication) {
		return ImmutableMap.of("name", authentication.getName(), "authorities", authentication.getAuthorities());
	}

	@PreAuthorize("hasAuthority('WRITE')")
	@PostMapping("/write")
	public Object write(OAuth2Authentication authentication) {
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
		OAuth2AccessToken token = tokenStore.readAccessToken(details.getTokenValue());
		return token.getAdditionalInformation().getOrDefault("userDetails", null);
	}
}
