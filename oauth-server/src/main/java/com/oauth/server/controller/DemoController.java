package com.oauth.server.controller;

import com.google.code.kaptcha.Producer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Cheng Yufei
 * @create 2020-11-13 6:02 下午
 **/
@RestController
@RequestMapping("/demo")
@Slf4j
public class DemoController {

    @Autowired
    private Producer producer;
    @Value("${server.port}")
    private Integer port;
    @Autowired
    private SessionRegistry sessionRegistry;
    @Autowired
    private RedisIndexedSessionRepository redisIndexedSessionRepository;

    @GetMapping("/index")
    public ModelAndView index() {
        return new ModelAndView("index");
    }

    /**
     * 验证码
     * @param response
     * @param session
     * @throws IOException
     */
    @GetMapping("/produceCode")
    public void produceCode(HttpServletResponse response, HttpSession session) throws IOException {
        response.setContentType("image/jpeg");
        String text = producer.createText();
        log.info("code:{}", text);
        session.setAttribute("verify_code", text);
        BufferedImage image = producer.createImage(text);
        ServletOutputStream outputStream = response.getOutputStream();
        ImageIO.write(image, "jpg", outputStream);
        outputStream.close();
    }

    /**
     * spring session, 分布式session测试
     * @param session
     * @return
     */
    @GetMapping("/setSession")
    public String session(HttpSession session) {
        session.setAttribute("name", "Taylor·Swift");
        return String.valueOf(port);
    }

    @GetMapping("/getSession")
    public String getSession(HttpSession session, String key) {
        return session.getAttribute(key) + ">>>" + port;
    }

    @GetMapping("/accessDenied")
    public String accessDenied() {
        return "测试无权访问的自定义异常";
    }

    /**
     * 获取在线用户：适用于 SessionRegistryImpl   的实现方式。spring session 不支持
     * @return
     */
    @GetMapping("/onlineNum")
    public String onlineNum() {
        List<Object> collect = sessionRegistry.getAllPrincipals().stream().filter(u -> !sessionRegistry.getAllSessions(u, false).isEmpty())
                .collect(Collectors.toList());
        return collect.size() + "";
    }

    @GetMapping("/onlineNum2")
    public String onlineNum2(@RequestParam String pattern) {
        RedisOperations<Object, Object> sessionRedisOperations = redisIndexedSessionRepository.getSessionRedisOperations();
        Set<Object> keys = sessionRedisOperations.keys(pattern);
        System.out.println(keys);
        return keys.size() + "";
    }
}
