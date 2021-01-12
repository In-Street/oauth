import org.bouncycastle.jcajce.provider.digest.MD5;
import org.jasypt.util.text.BasicTextEncryptor;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.DigestUtils;
import sun.misc.BASE64Encoder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
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
    }

    @Test
    public void password() throws NoSuchAlgorithmException {

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        System.out.println(passwordEncoder.encode("swift"));

        System.out.println(passwordEncoder.matches("writer", "$2a$10$Du3s4X6ufXGrHBPsUAH5Ie0S8UHroZDtcNB/oUfEdR5PSbKzK7hSi"));


        String md5 = DigestUtils.md5DigestAsHex("writer".getBytes());
        System.out.println("MD5加密:" + md5);


        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update("writer".getBytes());
        String md52 = new BigInteger(1, messageDigest.digest()).toString(16);
        System.out.println("MD5加密2:" + md52);

    }

    @Test
    public void textEncrypt() {
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword("");
        System.out.println(encryptor.encrypt(""));

    }

}
