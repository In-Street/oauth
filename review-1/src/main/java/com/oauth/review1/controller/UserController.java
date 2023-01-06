package com.oauth.review1.controller;

import com.google.common.collect.ImmutableMap;
import jdk.nashorn.internal.ir.annotations.Immutable;
import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 *
 * @author Cheng Yufei
 * @create 2022-08-30 09:27
 **/
@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/get")
    public Map get() throws IOException {
        String s = IOUtils.resourceToString("application.yml", StandardCharsets.UTF_8, UserController.class.getClassLoader());
        return ImmutableMap.of("username", "我们的爱", "address", "Luke", "resource", s);
    }

    @GetMapping("/admin")
    public Map admin() throws IOException {
        return ImmutableMap.of("username", "admin-简单爱");
    }

    @GetMapping("/user")
    public Map user() throws IOException {
        return ImmutableMap.of("username", "user-promise");
    }

    @GetMapping("/remember")
    public Map remember() throws IOException {
        return ImmutableMap.of("username", "remember");
    }
}
