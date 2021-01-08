package com.oauth.user.controller;

import com.google.common.collect.ImmutableMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

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

    /////////////////////////////////////////////使用表达式控制方法权限////////////////////////////////////////////////////////////

    /**
     *
     * @PreAuthorize：方法执行前进行权限检查
     * @PostAuthorize：方法执行后进行权限检查
     * @Secured：类似于 @PreAuthorize
     *
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
        //获取ip、sessionid或token信息
        Object details = authentication1.getDetails();

        return ImmutableMap.of("name", authentication.getName(), "authorities", authentication.getAuthorities(), "isAuthenticated",
                authentication1.isAuthenticated() + ">>>" + authentication1.getName(),
                "ip-sessionid", details);
    }

    /**
     * 登录用户的名字必须是writer
     * @return
     */
    @PreAuthorize("authentication.name.equals('writer')")
    @GetMapping("/writeName")
    public Map writeName() {
        return ImmutableMap.of("result", "我的名字是writer，所以有权限访问");
    }

    @PreAuthorize("#age>28")
    @GetMapping("/writeAgeGt")
    public Map writeAgeGt(@RequestParam Integer age) {
        return ImmutableMap.of("result", "我的age>28，所以有权限访问");
    }

    /////////////////////////////////////////////使用过滤注解////////////////////////////////////////////////////////////

    /**
     * 方法中有多个参数，使用 filterTarget 指定
     * @param ages
     * @param users
     * @return
     */
    @PreFilter(filterTarget = "ages", value = "filterObject%2==0")
    @GetMapping("/writePreFilter")
    public Map writePreFilter(@RequestParam List<Integer> ages, @RequestParam List<String> users) {
        return ImmutableMap.of("ages", ages, "users", users);
    }

    /**
     * filterObject: 过滤的元素
     *
     * @return 以2结尾的
     */
    @PostFilter("filterObject.lastIndexOf('2')!=-1")
    @GetMapping("/writePostFilter")
    public List<String> writePostFilter() {
        return Stream.iterate(1, k -> ++k).limit(20).map(String::valueOf).collect(Collectors.toList());
    }
}
