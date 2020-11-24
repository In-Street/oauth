package com.oauth.user.controller;

import com.google.common.collect.ImmutableMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
 *@PreAuthorize("hasRole()"),使用hasRole的话，数据库中的authorities表中需设置为 ROLE_ 开头的角色
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
    //@PreAuthorize("hasAuthority('READ') or hasAuthority('WRITE')")
    @PreAuthorize("hasAnyAuthority('READ','WRITE')")
    //@PreAuthorize("hasAnyRole('ROLE_READ','ROLE_WRITE')")
    //@PreAuthorize("hasRole('ROLE_READ')")
    @GetMapping("/common/read")
    public Map read(OAuth2Authentication authentication) {
        return ImmutableMap.of("name", authentication.getName(), "authorities", authentication.getAuthorities());
    }

    @PreAuthorize("hasAuthority('WRITE')")
    //@PreAuthorize("hasRole('WRITE')")
    @PostMapping("/common/write")
    public Object write(OAuth2Authentication authentication) {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
        OAuth2AccessToken token = tokenStore.readAccessToken(details.getTokenValue());
        return token.getAdditionalInformation().getOrDefault("userDetail", null);
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    //@PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public Map admin(OAuth2Authentication authentication) {
        //最新用户信息可以从 SecurityContextHolder 中获取
        Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
        return ImmutableMap.of("name", authentication.getName(), "authorities", authentication.getAuthorities(),"isAuthenticated",authentication1.isAuthenticated()+">>>"+authentication1.getName());
    }

}
