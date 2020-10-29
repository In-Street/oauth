package com.oauth.server.config;


import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class WebSecurityConfigTest {

	@Test
	public void jks() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(new File("D:/jwt.jks")),"oauthswift".toCharArray());


		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			String s = aliases.nextElement();
			System.out.println(s);
		}

	}

}