package com.oauth.review1.controller;

import com.google.common.collect.ImmutableMap;
import jdk.nashorn.internal.ir.annotations.Immutable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public Map get(){
        return ImmutableMap.of("username", "我们的爱", "address", "Luke");
    }
}
