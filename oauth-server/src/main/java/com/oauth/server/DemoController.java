package com.oauth.server;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author Cheng Yufei
 * @create 2020-11-13 6:02 下午
 **/
@RestController
@RequestMapping("/demo")
public class DemoController {

    @GetMapping("/index")
    public ModelAndView index() {
        return new ModelAndView("index");
    }
}
