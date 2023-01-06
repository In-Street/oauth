import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.Base64Utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.SecureRandom;
import java.util.Base64;

/**
 *
 * @author Cheng Yufei
 * @create 2022-09-23 16:35
 **/
public class TestSecurity {
    
    @Test
    public void rememberMe() throws UnsupportedEncodingException {

        String str = "cFVHclIxU2xxV0pTZ2VxRFVqeklnUSUzRCUzRDp5akU4WFlMSXdpQ1RSNmVKNTdnejZRJTNEJTNE";
       /* int len = str.length();
        for (int i = 0; i < len % 4; i++) {
            str =str+ "=";
        }*/

        //admin:1665131606676:67c7e62562c89dcf7bb8b2d8a288127a
        System.out.println(new String(Base64Utils.decodeFromString(str)));

        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        String s = new String(Base64Utils.encode(bytes));
        System.out.println(s);


        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        System.out.println(passwordEncoder.encode("user"));
    }
}
