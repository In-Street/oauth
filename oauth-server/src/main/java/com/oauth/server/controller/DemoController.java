package com.oauth.server.controller;

import com.google.code.kaptcha.Producer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;

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

    @GetMapping("/index")
    public ModelAndView index() {
        return new ModelAndView("index");
    }

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
}
