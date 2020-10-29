package com.oauth.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;

/**
 * 配置授权服务器
 * @author Cheng Yufei
 * @create 2020-10-29 10:43
 **/
@Configuration
@EnableAuthorizationServer
public class OAuth2ServerConfiguration extends AuthorizationServerConfigurerAdapter {


	@Autowired
	private DataSource dataSource;
	@Autowired
	private AuthenticationManager authenticationManager;

	/**
	 * 使用数据库维护客户端信息
	 * @param clients
	 * @throws Exception
	 */
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource);
	}


	/**
	 * 打开验证Token访问权限；
	 *
	 * 允许ClientSecret明文方式保存，并且可以通过表单提交（而不仅仅是Basic Auth方式提交）
	 * @param security
	 * @throws Exception
	 */
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()")
				.allowFormAuthenticationForClients().passwordEncoder(NoOpPasswordEncoder.getInstance());
	}


	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		/*endpoints.approvalStore(approvalStore())
				.tokenStore()*/
	}
	
	@Bean(name="jdbcApprovalStore")
	public JdbcApprovalStore approvalStore(){
		return new JdbcApprovalStore(dataSource);
	}
	
	@Bean(name="jwtTokenStore ")
	public JwtTokenStore tokenStore(){
		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "oauthswift".toCharArray());
		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));
		return new JwtTokenStore(tokenConverter);
	}
}
