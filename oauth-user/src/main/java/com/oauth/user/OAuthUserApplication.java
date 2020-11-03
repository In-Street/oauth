package com.oauth.user;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 *
 * @author Cheng Yufei
 * @create 2020-10-29 10:38
 **/
@SpringBootApplication(scanBasePackages = {"com.oauth.user"})
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class OAuthUserApplication {


	public static void main(String[] args) {
		new SpringApplicationBuilder(OAuthUserApplication.class).run(args);
	}
}
