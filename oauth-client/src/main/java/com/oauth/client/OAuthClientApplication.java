package com.oauth.client;

import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.beans.factory.annotation.Value;
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
@SpringBootApplication(scanBasePackages = {"com.oauth.client"})
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class OAuthClientApplication {



	public static void main(String[] args) {
		new SpringApplicationBuilder(OAuthClientApplication.class).run(args);
	}
}
