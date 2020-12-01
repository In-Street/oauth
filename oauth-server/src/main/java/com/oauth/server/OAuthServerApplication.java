package com.oauth.server;

import com.google.code.kaptcha.Producer;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.PropertySource;

import java.util.Properties;

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

	@Bean
	public Producer verifyCode() {
		Properties properties = new Properties();
		properties.setProperty("kaptcha.image.width", "150");
		properties.setProperty("kaptcha.image.height", "50");
		properties.setProperty("kaptcha.textproducer.char.string", "0123456789");
		properties.setProperty("kaptcha.textproducer.char.length", "4");
		Config config = new Config(properties);
		DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
		defaultKaptcha.setConfig(config);
		return defaultKaptcha;
	}
}
