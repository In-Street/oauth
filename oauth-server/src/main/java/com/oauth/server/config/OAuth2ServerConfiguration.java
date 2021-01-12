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
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import sun.security.util.Pem;

import javax.sql.DataSource;
import java.io.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;

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
	@Autowired
	private UserDetailsService userDetailsService;

	/**
	 * 使用数据库维护客户端信息
	 * @param clients
	 * @throws Exception
	 */
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		/*在内存中配置客户端，方便测试
		clients.inMemory()
				.withClient("CYF")
				.secret(passwordEncoder.encode("123"))
				.resourceIds("res1")
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("all")
				.redirectUris("http://localhost:xxx");*/
		clients.jdbc(dataSource);
	}


	/**
	 * 打开验证Token访问权限；
	 *
	 * Client的client_secret以BCrypt加密，并且可以通过表单提交（而不仅仅是Basic Auth方式提交）
	 * @param security
	 * @throws Exception
	 */
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()")
				.passwordEncoder(new BCryptPasswordEncoder())
				//没有此设置的话，请求Header中添加 Authorization: Basic encoder 。encoder是  String str=用户名:密码, encoder = Base64 encoder(str)
				.allowFormAuthenticationForClients();
	}


	/**
	 * 配置令牌的访问端点和令牌服务。
	 *   1。配置Token存放方式，不是内存、数据库等，以JWT存储；
	 *
	 *   2。配置用户授权批准记录存储方式；
	 *
	 *   3。自定义Token增强器，将更多信息存入Token中；
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
				//指定userDetailsService，refresh_token时会使用，否则报 UserDetailService is required，但也能刷新成功
				.userDetailsService(userDetailsService)
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
	 *配置JWT，使用非对称加密方式验证，实现将登录用户信息和 JWT 进行转换
	 * @return
	 */
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() throws IOException {

		Security.addProvider(new BouncyCastleProvider());

		//本地启动可以文件形式读取
		/*File priKeyFile = new PathMatchingResourcePatternResolver().getResource("classpath:prikey.pem").getFile();
		PEMParser parserPri = new PEMParser(new FileReader(priKeyFile));*/

		// jar包部署时需以流的形式读取，否则 报【cannot be resolved to absolute file path】
		InputStream inputStream = new PathMatchingResourcePatternResolver().getResource("classpath:prikey.pem").getInputStream();
		PEMParser parserPri = new PEMParser(new InputStreamReader(inputStream));

		JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		Object o = parserPri.readObject();
		KeyPair keyPair = converter.getKeyPair(((PEMKeyPair) o));

		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setKeyPair(keyPair);
		//签名字符串
		//tokenConverter.setSigningKey();

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
				e.printStackTrace();

				ResponseEntity<OAuth2Exception> responseEntity = super.translate(e);
				HttpHeaders headers = new HttpHeaders();
				headers.setAll(responseEntity.getHeaders().toSingleValueMap());
				OAuth2Exception excBody = responseEntity.getBody();
				return new ResponseEntity<>(excBody, headers, responseEntity.getStatusCode());
			}
		};
	}

  //配置Token的存储、刷新、有效期等
	/*@Bean
	AuthorizationServerTokenServices tokenServices() {
		DefaultTokenServices services = new DefaultTokenServices();
		services.setClientDetailsService(clientDetailsService);
		services.setSupportRefreshToken(true);
		services.setTokenStore(tokenStore);
		services.setAccessTokenValiditySeconds(60 * 60 * 24 * 2);
		services.setRefreshTokenValiditySeconds(60 * 60 * 24 * 7);
		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter));
		services.setTokenEnhancer(tokenEnhancerChain);
		return services;
	}*/
}
