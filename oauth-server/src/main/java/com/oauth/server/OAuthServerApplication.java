package com.oauth.server;

import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.PropertySource;

/**
 *
 * @author Cheng Yufei
 * @create 2020-10-29 10:38
 **/
@SpringBootApplication(scanBasePackages = {"com.oauth.server"})
@EnableAspectJAutoProxy(proxyTargetClass = true)
@PropertySource(value = {"file:/Users/chengyufei/Downloads/project/self/encrypt.properties"})
public class OAuthServerApplication {

	@Value("${jasypt.encryptor.password}")
	private String saltValue;


	public static void main(String[] args) {
		new SpringApplicationBuilder(OAuthServerApplication.class).run(args);
	}
	/**
	 *设置jasypt加/解密类
	 * @return
	 */
	@Bean
	public BasicTextEncryptor basicTextEncryptor() {
		BasicTextEncryptor encryptor = new BasicTextEncryptor();
		encryptor.setPassword(saltValue);
		return encryptor;
	}
}
