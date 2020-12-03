package com.oauth.user.config;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * 受保护资源服务器配置
 * @author Cheng Yufei
 * @create 2020-11-02 15:05
 **/
@Configuration
//启用资源服务器
@EnableResourceServer
//启用方法注解进行权限控制
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    /**
     * 配置资源服务器的TokenStore为JWT及公钥；
     * 声明配置资源服务器的ID为：oauth-user;
     * @param resources
     * @throws Exception
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId("oauth-user").tokenStore(tokenStore());
    }

    /**
     * 1.不重写此方法时，默认拦截所有请求接口，接口方法不标注 @PreAuthorize("hasAuthority('READ') or hasAuthority('WRITE')") 所需权限时，只有read权限的账号也可以访问。
     * 2.除 /user 下的请求都允许匿名访问。
     * 3.注意 authenticated() 和 permitAll() 位置，决定matchers的接口是需要授权还是都可访问。
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/user/**")
                .authenticated()
                .anyRequest().permitAll();
    }

    @Bean(name = "tokenStore")
    public TokenStore tokenStore() throws IOException {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        File pubKeyFile = new PathMatchingResourcePatternResolver().getResource("classpath:pubkey.pem").getFile();
        PEMParser pemParser = new PEMParser(new FileReader(pubKeyFile));
        PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey(((SubjectPublicKeyInfo) pemParser.readObject()));

        jwtAccessTokenConverter.setVerifier(new RsaVerifier(((RSAPublicKey) publicKey)));
        return new JwtTokenStore(jwtAccessTokenConverter);

    }
}
