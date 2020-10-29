import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;

/**
 *
 * @author Cheng Yufei
 * @create 2020-10-29 15:29
 **/
public class TestD {

	@Test
	public void jks() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(new File("D:/jwt.jks")),"oauthswift".toCharArray());


		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			String s = aliases.nextElement();
			System.out.println(s);
		}

		PublicKey publicKey = keyStore.getCertificate("mykey").getPublicKey();

		String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		System.out.println(publicKeyStr);

	}

}
