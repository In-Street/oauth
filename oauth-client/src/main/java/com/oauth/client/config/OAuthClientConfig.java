package com.oauth.client.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

/**
 * @EnableOAuth2Sso 中存在 WebSecurityConfig过滤链，会拦截所有请求。直接导致后面自定义的WebSecurityConfig，@Order(200)的拦截无效，所有请求
 * 都会跳转到授权服务器的登录页。
 * 当把自定义的WebSecurityConfig的Order设定到小于100时，会优先使用此过滤链，让定义的某些接口能直接permitAll，但是无法跳转到授权服务器的登录页
 *
 * @author Cheng Yufei
 * @create 2020-11-06 17:16
 **/
@Configuration
@EnableOAuth2Sso
//@EnableOAuth2Client
public class OAuthClientConfig  {

    @Bean(name = "oAuth2RestTemplate")
    public OAuth2RestTemplate init(OAuth2ClientContext oAuth2ClientContext, OAuth2ProtectedResourceDetails resourceDetails) {
        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(resourceDetails, oAuth2ClientContext);
        return oAuth2RestTemplate;
    }
}
