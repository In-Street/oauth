import org.junit.Test;
import org.springframework.util.Base64Utils;

/**
 *
 * @author Cheng Yufei
 * @create 2022-09-23 16:35
 **/
public class TestSecurity {
    
    @Test
    public void rememberMe() {

        String str = "YWRtaW46MTY2NTEzMTYwNjY3Njo2N2M3ZTYyNTYyYzg5ZGNmN2JiOGIyZDhhMjg4MTI3YQ";

        //admin:1665131606676:67c7e62562c89dcf7bb8b2d8a288127a
        System.out.println(new String(Base64Utils.decodeFromString(str)));
    }
}
