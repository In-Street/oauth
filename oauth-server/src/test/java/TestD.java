import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import sun.misc.BASE64Encoder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
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
		keyStore.load(new FileInputStream(new File("D:/jwt.jks")), "oauthswift".toCharArray());


		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			String s = aliases.nextElement();
			System.out.println(s);
		}

		PublicKey publicKey = keyStore.getCertificate("mykey").getPublicKey();

		String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		System.out.println(publicKeyStr);
		System.out.println("............");


		BASE64Encoder encoder = new BASE64Encoder();
		String encoded = encoder.encode(publicKey.getEncoded());
		FileWriter fileWriter = new FileWriter(new File("D:/pub.txt"));
		fileWriter.write("-----Begin Public Key-----\r\n");//非必须
		fileWriter.write(encoded);
		fileWriter.write("\r\n-----End Public Key-----");//非必须
		fileWriter.close();


	}

	@Test
	public void password() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String reader = encoder.encode("reader");
		System.out.println(reader);
	}

	@Test
	public void publicKey() {
		byte[] bytes = Base64.getDecoder().decode("eyJhdWQiOlsib2F1dGgtdXNlciJdLCJ1c2VyX25hbWUiOiJyZWFkZXIiLCJ1c2VyRGV0YWlsIjp7InBhc3N3b3JkIjpudWxsLCJ1c2VybmFtZSI6InJlYWRlciIsImF1dGhvcml0aWVzIjpbeyJhdXRob3JpdHkiOiJSRUFEIn1dLCJhY2NvdW50Tm9uRXhwaXJlZCI6dHJ1ZSwiYWNjb3VudE5vbkxvY2tlZCI6dHJ1ZSwiY3JlZGVudGlhbHNOb25FeHBpcmVkIjp0cnVlLCJlbmFibGVkIjp0cnVlfSwic2NvcGUiOlsiRk9PIl0sImV4cCI6MTYwNDM5MjY3OSwiYXV0aG9yaXRpZXMiOlsiUkVBRCJdLCJqdGkiOiI1MDc3OWY1OS1lOGMwLTQ1ZDYtYjFkZC05MGFkODJlMGE0OTciLCJjbGllbnRfaWQiOiJ1c2Vyc2VydmljZTMifQ");

		System.out.println(new String(bytes));

	}


}
