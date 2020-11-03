package com.oauth.server.config;

import com.google.common.collect.Lists;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import sun.security.util.Pem;

import javax.sql.DataSource;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

/**
 *
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


	/**
	 * 配置Token存放方式，不是内存、数据库等，以JWT存储；
	 *
	 * 配置用户授权批准记录存储方式；
	 *
	 * 自定义Token增强器，将更多信息存入Token中；
	 *
	 * @param endpoints
	 * @throws Exception
	 */
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Lists.newArrayList(new CustomTokenEnhancer(),jwtAccessTokenConverter()));

		endpoints.approvalStore(approvalStore())
				.tokenStore(new JwtTokenStore(jwtAccessTokenConverter()))
				.authenticationManager(authenticationManager)
				.authorizationCodeServices(authorizationCodeServices())
				.tokenEnhancer(tokenEnhancerChain)
				.exceptionTranslator(loggingExceptionTranslator());
	}

	/**
	 * 使用数据库保存用户授权批准记录
	 * @return
	 */
	@Bean(name="jdbcApprovalStore")
	public JdbcApprovalStore approvalStore(){
		return new JdbcApprovalStore(dataSource);
	}

	/**
	 *配置JWT，使用非堆成加密方式验证
	 * @return
	 */
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() throws IOException {

		File priKeyFile = new PathMatchingResourcePatternResolver().getResource("classpath:prikey.pem").getFile();
		Security.addProvider(new BouncyCastleProvider());
		PEMParser parserPri = new PEMParser(new FileReader(priKeyFile));
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		Object o = parserPri.readObject();
		KeyPair keyPair = converter.getKeyPair(((PEMKeyPair) o));

		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setKeyPair(keyPair);

		return tokenConverter;
	}

	/**
	 * 使用数据库保存授权码
	 * @return
	 */
	@Bean(name="jdbcAuthorizationCodeServices")
	public JdbcAuthorizationCodeServices authorizationCodeServices(){
		return new JdbcAuthorizationCodeServices(dataSource);
	}

	@Bean
	public WebResponseExceptionTranslator loggingExceptionTranslator() {
		return new DefaultWebResponseExceptionTranslator() {
			@Override
			public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
				// This is the line that prints the stack trace to the log. You can customise this to format the trace etc if you like
				e.printStackTrace();

				// Carry on handling the exception
				ResponseEntity<OAuth2Exception> responseEntity = super.translate(e);
				HttpHeaders headers = new HttpHeaders();
				headers.setAll(responseEntity.getHeaders().toSingleValueMap());
				OAuth2Exception excBody = responseEntity.getBody();
				return new ResponseEntity<>(excBody, headers, responseEntity.getStatusCode());
			}
		};
	}
}
