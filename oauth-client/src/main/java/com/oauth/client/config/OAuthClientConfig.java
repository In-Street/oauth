package com.oauth.client.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * @author Cheng Yufei
 * @create 2020-11-06 17:16
 **/
@Configuration
@EnableOAuth2Sso
public class OAuthClientConfig {

    @Bean(name = "oAuth2RestTemplate")
    public OAuth2RestTemplate init(OAuth2ClientContext oAuth2ClientContext, OAuth2ProtectedResourceDetails resourceDetails) {
        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(resourceDetails, oAuth2ClientContext);
        return oAuth2RestTemplate;
    }
}
